
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t                       name;
    time_t                          expires_time;
    ngx_str_t                       domain;
    ngx_str_t                       path;
    ngx_http_complex_value_t        *value;
} ngx_http_source_cookie_loc_conf_t;

static ngx_int_t ngx_http_source_cookie_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_source_cookie_parse(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t ngx_http_source_cookie_set(ngx_http_request_t *r, ngx_http_source_cookie_loc_conf_t *conf);

static void *ngx_http_source_cookie_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_source_cookie_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_source_cookie_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_source_cookie_commands[] = {

    { ngx_string("source_cookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE12,
      ngx_http_source_cookie_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("source_cookie_domain"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_source_cookie_loc_conf_t, domain),
      NULL },

    { ngx_string("source_cookie_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_source_cookie_loc_conf_t, path),
      NULL },

    { ngx_string("source_cookie_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_source_cookie_loc_conf_t, expires_time),
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_http_source_cookie_module_ctx = {
    NULL,                             /* preconfiguration */
    ngx_http_source_cookie_init,             /* postconfiguration */

    NULL,                             /* create main configuration */
    NULL,                             /* init main configuration */

    NULL,                             /* create server configuration */
    NULL,                             /* merge server configuration */

    ngx_http_source_cookie_create_loc_conf,  /* create location configuration */
    ngx_http_source_cookie_merge_loc_conf    /* merge location configuration */
};

ngx_module_t ngx_http_source_cookie_module = {
    NGX_MODULE_V1,
    &ngx_http_source_cookie_module_ctx,      /* module context */
    ngx_http_source_cookie_commands,         /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t
ngx_http_source_cookie_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                           rc;
    ngx_http_source_cookie_loc_conf_t   *sclc;
    ngx_str_t                           value;

    sclc = ngx_http_get_module_loc_conf(r, ngx_http_source_cookie_module);

    if((sclc->name.len == 0)
        || r != r->main
        || r->internal
        || r->error_page
        || r->post_action)
    {
        return ngx_http_next_header_filter(r);
    }

    rc = ngx_http_source_cookie_parse(r, &value);

    if(rc == NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    rc = ngx_http_source_cookie_set(r, sclc);    

    if(rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_source_cookie_parse(ngx_http_request_t *r, ngx_str_t *value) {
    ngx_int_t                          rc;
    ngx_http_source_cookie_loc_conf_t  *sclc;

    sclc = ngx_http_get_module_loc_conf(r, ngx_http_source_cookie_module);

    /*
     * Find the cookie
     */
    rc = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
        &sclc->name, value);

    if(rc == NGX_DECLINED) {
        return rc;
    }

    return NGX_OK;
}

/*
 * This function is pretty much like ngx_http_userid_set_uid,
 * but can you do better?
 */
static ngx_int_t
ngx_http_source_cookie_set(ngx_http_request_t *r, ngx_http_source_cookie_loc_conf_t *conf)
{
    u_char           *cookie, *p;
    size_t            len;
    ngx_table_elt_t  *set_cookie;
    ngx_int_t         expires;
    ngx_str_t         value;

    if(conf->value == NULL) {
        return NGX_OK;
    }

    if(ngx_http_complex_value(r, conf->value, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    if(value.len == 0) {
        return NGX_OK;
    }

    expires = ngx_time() + conf->expires_time;

    len = conf->name.len + 1 + value.len;

    if(conf->expires_time != 0) {
        len += sizeof("; expires=") - 1 +
            sizeof("Mon, 01 Sep 1970 00:00:00 GMT") - 1;
    }

    if(conf->domain.len) {
        len += conf->domain.len;
    }

    if(conf->path.len) {
        len += conf->path.len;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, conf->name.data, conf->name.len);
    *p++ = '=';
    p = ngx_copy(p, value.data, value.len);

    if(conf->expires_time != 0) {
        p = ngx_cpymem(p, "; expires=", sizeof("; expires=") - 1);
        p = ngx_http_cookie_time(p, expires);
    }

    p = ngx_copy(p, conf->domain.data, conf->domain.len);

    p = ngx_copy(p, conf->path.data, conf->path.len);

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "set cookie: \"%V\"", &set_cookie->value);

    return NGX_OK;
}

static void *
ngx_http_source_cookie_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_source_cookie_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_source_cookie_loc_conf_t));

    if(conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->expires_time = NGX_CONF_UNSET;
    conf->value = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_source_cookie_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_source_cookie_loc_conf_t *prev = parent;
    ngx_http_source_cookie_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->name, prev->name, "");
    ngx_conf_merge_value(conf->expires_time, prev->expires_time, 0);

    ngx_conf_merge_str_value(conf->domain, prev->domain, "");
    ngx_conf_merge_str_value(conf->path, prev->path, "");

    ngx_conf_merge_ptr_value(conf->value, prev->value, NULL);

    return NGX_CONF_OK;
}

static char *
ngx_http_source_cookie_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_source_cookie_loc_conf_t *sclc = conf;
    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t  ccv;
    
    if(sclc->name.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sclc->name = value[1];

    if(cf->args->nelts > 2) {
        sclc->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if(sclc->value == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[2];
        ccv.complex_value = sclc->value;

        if(ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_source_cookie_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_source_cookie_header_filter;

    return NGX_OK;
}
