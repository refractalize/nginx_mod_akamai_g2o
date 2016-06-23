/*
 * nginx (c) Igor Sysoev
 * ngx_http_accesskey_module (C) Mykola Grechukh <gns@altlinux.org>
 * adapted to Akamai G2O (C) Tim Macfarlane <timmacfarlane@gmail.com>
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

enum {
    G2O_MODE_OFF,            // no G2O validation
    G2O_MODE_PASSIVE,        // validate G2O but don't fail any requests
    G2O_MODE_ON,            // validate G2O and fail the request if invalid
};

typedef struct {
    ngx_int_t     mode;
    ngx_str_t     nonce;
    ngx_str_t     key;
    ngx_str_t     data_header;
    ngx_str_t     sign_header;
    const EVP_MD* (*hash_function)(void);
    ngx_uint_t    version;
    time_t        time_window;
    ngx_uint_t    log_level;
} ngx_http_akamai_g2o_loc_conf_t;

static ngx_int_t ngx_http_akamai_g2o_handler(ngx_http_request_t *r);

static void *ngx_http_akamai_g2o_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_akamai_g2o_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_akamai_g2o_hash_function_command(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_akamai_g2o_init(ngx_conf_t *cf);

static void base64_signature_of_data(ngx_http_request_t *r, ngx_str_t data, ngx_str_t key, u_char *signature);
static int try_get_auth_data_fields(ngx_str_t data, u_int *version, u_int *time, ngx_str_t *nonce);
static char *ngx_http_akamai_g2o_mode_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_akamai_g2o_log_level_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_akamai_g2o_commands[] = {
    { ngx_string("g2o"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_akamai_g2o_mode_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, mode),
      NULL },

    { ngx_string("g2o_nonce"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, nonce),
      NULL },

    { ngx_string("g2o_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, key),
      NULL },

    { ngx_string("g2o_data_header"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, data_header),
      NULL },

    { ngx_string("g2o_sign_header"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, sign_header),
      NULL },

    { ngx_string("g2o_hash_function"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_akamai_g2o_hash_function_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("g2o_version"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, version),
      NULL },

    { ngx_string("g2o_time_window"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, time_window),
      NULL },

    { ngx_string("g2o_log_level"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_akamai_g2o_log_level_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, log_level),
      NULL },

      ngx_null_command
};

static ngx_str_t err_levels[] = {
    ngx_null_string,
    ngx_string("emerg"),
    ngx_string("alert"),
    ngx_string("crit"),
    ngx_string("error"),
    ngx_string("warn"),
    ngx_string("notice"),
    ngx_string("info"),
    ngx_string("debug")
};

static ngx_http_module_t  ngx_http_akamai_g2o_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_akamai_g2o_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_akamai_g2o_create_loc_conf,       /* create location configuration */
    ngx_http_akamai_g2o_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_akamai_g2o_module = {
    NGX_MODULE_V1,
    &ngx_http_akamai_g2o_module_ctx,           /* module context */
    ngx_http_akamai_g2o_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_akamai_g2o_mode_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_akamai_g2o_loc_conf_t    *g2o_conf = conf;
    ngx_str_t                       *value;

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0)
    {
        g2o_conf->mode = G2O_MODE_OFF;
    }
    else if (ngx_strcasecmp(value[1].data, (u_char *) "passive") == 0)
    {
        g2o_conf->mode = G2O_MODE_PASSIVE;
    }
    else if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0)
    {
        g2o_conf->mode = G2O_MODE_ON;
    }
    else
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid value \"%s\" in \"%s\" directive, "
            "it must be \"off\", \"on\" or \"passive\"",
            value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_akamai_g2o_log_level_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_akamai_g2o_loc_conf_t    *g2o_conf = conf;
    ngx_str_t                       *value;
    ngx_uint_t   n;

    value = cf->args->elts;

    for (n = 1; n <= NGX_LOG_DEBUG; n++)
    {
        if (ngx_strcmp(value[1].data, err_levels[n].data) == 0) 
        {
            g2o_conf->log_level = n;
            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "invalid value \"%s\" in \"%s\" directive",
        value[1].data, cmd->name.data);
    return NGX_CONF_ERROR;
}

static void 
get_data_and_sign_from_request_headers(ngx_http_request_t *r, ngx_str_t *header_data, ngx_str_t *header_sign) {
    ngx_http_akamai_g2o_loc_conf_t  *alcf;
    ngx_list_t headers = r->headers_in.headers;
    ngx_list_part_t *part = &headers.part;
    ngx_table_elt_t* data = part->elts;
    ngx_table_elt_t header;

    unsigned int i;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_akamai_g2o_module);

    for (i = 0 ;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

        header = data[i];
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s: %s", header.key.data, header.value.data);

        if (ngx_strcasecmp(alcf->data_header.data, header.key.data) == 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "found %V", &alcf->data_header);
            *header_data = header.value;
        }
        if (ngx_strcasecmp(alcf->sign_header.data, header.key.data) == 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "found %V", &alcf->sign_header);
            *header_sign = header.value;
        }
    }
}

static int 
check_has_g2o_headers(ngx_http_request_t *r, ngx_http_akamai_g2o_loc_conf_t  *alcf) {
    ngx_str_t header_data = ngx_null_string, header_sign = ngx_null_string;
    get_data_and_sign_from_request_headers(r, &header_data, &header_sign);

    if (!header_data.data) {
        ngx_log_error(alcf->log_level, r->connection->log, 0, "g2o missing data header");
        return 0;
    }

    if (!header_sign.data) {
        ngx_log_error(alcf->log_level, r->connection->log, 0, "g2o missing sign header");
        return 0;
    }

    // for base64 we need: ceiling(32 / 3) * 4 + 1 = 45 bytes
    // where 32 is SHA256 digest length
    // + 1 for the string termination char
    // lets call it 60, just in case
    u_char signature [60];

    // signature is correct
    base64_signature_of_data(r, header_data, alcf->key, signature);

    u_int version, auth_time;
    ngx_str_t nonce;

    if (!try_get_auth_data_fields(header_data, &version, &auth_time, &nonce)) {
        ngx_log_error(alcf->log_level, r->connection->log, 0, "g2o data not formatted correctly %V", &header_data);
        return 0;
    }

    time_t current_time = ngx_time();

    // request using correct version of G2O
    if (version != alcf->version) {
        ngx_log_error(alcf->log_level, r->connection->log, 0, "g2o version %ud invalid", version);
        return 0;
    }

    // request not too far into the future
    if (auth_time > current_time + alcf->time_window) {
        ngx_log_error(alcf->log_level, r->connection->log, 0, "g2o auth time %ud too far into the future", auth_time);
        return 0;
    }

    // request not too old
    if (auth_time < current_time - alcf->time_window) {
        ngx_log_error(alcf->log_level, r->connection->log, 0, "g2o auth time %ud too old", auth_time);
        return 0;
    }

    // nonce is correct
    if (ngx_strcmp(nonce.data, alcf->nonce.data)) {
        ngx_log_error(alcf->log_level, r->connection->log, 0, "g2o nonce %V incorrect", &nonce);
        return 0;
    }

    if (ngx_strncmp(header_sign.data, signature, header_sign.len)) {
        ngx_log_error(alcf->log_level, r->connection->log, 0, "g2o signature incorrect, expected '%s' got '%V'", signature, &header_sign);
        return 0;
    }

    // request past all checks, content is good to go!
    return 1;
}

static void 
base64_signature_of_data(ngx_http_request_t *r, ngx_str_t data, ngx_str_t key, u_char *signature) {
    ngx_http_akamai_g2o_loc_conf_t  *alcf;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    ngx_str_t base64_dest;
    ngx_str_t base64_src;
    HMAC_CTX hmac;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_akamai_g2o_module);

    HMAC_CTX_init(&hmac);
    HMAC_Init(&hmac, key.data, key.len, alcf->hash_function());
    HMAC_Update(&hmac, data.data, data.len);
    HMAC_Update(&hmac, r->unparsed_uri.data, r->unparsed_uri.len);
    HMAC_Final(&hmac, md, &md_len);
    HMAC_CTX_cleanup(&hmac);

    base64_src.data = md;
    base64_src.len = md_len;
    base64_dest.data = signature;

    ngx_encode_base64(&base64_dest, &base64_src);
    base64_dest.data[base64_dest.len] = '\0';
}

static u_char* 
get_next_auth_data_token(u_char* start, u_char* end, ngx_str_t* output)
{
	output->data = start;
	for (; start + 1 < end; start++)
	{
		if (start[0] == ',' && start[1] == ' ')
		{
			output->len = start - output->data;
			return start + 2;
		}
	}
	output->len = end - output->data;
	return end;
}

static int 
try_get_auth_data_fields(ngx_str_t data, u_int *version, u_int *time, ngx_str_t *nonce) {
	u_char* p = data.data;
	u_char* end = data.data + data.len;
	ngx_str_t cur_token;

	// version
	p = get_next_auth_data_token(p, end, &cur_token);
	if (cur_token.len == 0)
		return 0;
	*version = ngx_atoi(cur_token.data, cur_token.len);

	// ghost ip
	p = get_next_auth_data_token(p, end, &cur_token);
	if (cur_token.len == 0)
		return 0;

	// client ip
	p = get_next_auth_data_token(p, end, &cur_token);
	if (cur_token.len == 0)
		return 0;

	// time
	p = get_next_auth_data_token(p, end, &cur_token);
	if (cur_token.len == 0)
		return 0;
	*time = ngx_atoi(cur_token.data, cur_token.len);

	// unique id
	p = get_next_auth_data_token(p, end, &cur_token);
	if (cur_token.len == 0)
		return 0;

	// nonce
	p = get_next_auth_data_token(p, end, nonce);
	if (nonce->len == 0)
		return 0;

    return 1;
}

static ngx_int_t
ngx_http_akamai_g2o_handler(ngx_http_request_t *r)
{
    ngx_http_akamai_g2o_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_akamai_g2o_module);

    switch (alcf->mode) 
	{
	case G2O_MODE_OFF:
		break;

	case G2O_MODE_ON:
		if (!check_has_g2o_headers(r, alcf))
		{
			return NGX_HTTP_FORBIDDEN;
		}
		break;

	case G2O_MODE_PASSIVE:
		check_has_g2o_headers(r, alcf);
		break;
	}
	return NGX_OK;
}

static char *
ngx_http_akamai_g2o_hash_function_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_akamai_g2o_loc_conf_t    *g2o_conf = conf;
    ngx_str_t                       *value;

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "md5") == 0) {
        g2o_conf->hash_function = EVP_md5;
    }
    else if (ngx_strcasecmp(value[1].data, (u_char *) "sha1") == 0) {
        g2o_conf->hash_function = EVP_sha1;
    }
    else if (ngx_strcasecmp(value[1].data, (u_char *) "sha256") == 0) {
        g2o_conf->hash_function = EVP_sha256;
    }
    else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid value \"%s\" in \"%s\" directive, "
            "it must be \"md5\", \"sha1\" or \"sha256\"",
            value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_akamai_g2o_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_akamai_g2o_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_akamai_g2o_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->mode = NGX_CONF_UNSET;
    conf->hash_function = NGX_CONF_UNSET_PTR;
    conf->version = NGX_CONF_UNSET_UINT;
    conf->time_window = NGX_CONF_UNSET;
	conf->log_level = NGX_CONF_UNSET_UINT;
    return conf;
}


static char *
ngx_http_akamai_g2o_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_akamai_g2o_loc_conf_t  *prev = parent;
    ngx_http_akamai_g2o_loc_conf_t  *conf = child;
	ngx_conf_merge_value(conf->mode, prev->mode, G2O_MODE_OFF);
    ngx_conf_merge_str_value(conf->key, prev->key, "");
    ngx_conf_merge_str_value(conf->nonce,prev->nonce, "");
    ngx_conf_merge_str_value(conf->data_header, prev->data_header, "X-Akamai-G2O-Auth-Data");
    ngx_conf_merge_str_value(conf->sign_header, prev->sign_header, "X-Akamai-G2O-Auth-Sign");
    ngx_conf_merge_ptr_value(conf->hash_function, prev->hash_function, EVP_md5);
    ngx_conf_merge_uint_value(conf->version, prev->version, 3);
    ngx_conf_merge_value(conf->time_window, prev->time_window, 30);
	ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_DEBUG);

	if (conf->mode != G2O_MODE_OFF)
	{
		if (!conf->key.data) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
				"g2o_key not configured");
			return 0;
		}

		if (!conf->nonce.data) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
				"g2o_nonce not configured");
			return 0;
		}
	}

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_akamai_g2o_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_akamai_g2o_handler;

    return NGX_OK;
}
