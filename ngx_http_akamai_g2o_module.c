/*
 * nginx (c) Igor Sysoev
 * ngx_http_accesskey_module (C) Mykola Grechukh <gns@altlinux.org>
 * adapted to Akamai G2O (C) Tim Macfarlane <timmacfarlane@gmail.com>
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <openssl/buffer.h>

#define NGX_ACCESSKEY_MD5 1
#define NGX_ACCESSKEY_SHA1 2

typedef struct {
    ngx_flag_t    enable;
    ngx_str_t     arg;
    ngx_uint_t    hashmethod;
    ngx_str_t     signature;
    ngx_str_t     nonce;
    ngx_str_t     key;
    ngx_array_t  *signature_lengths;
    ngx_array_t  *signature_values;
} ngx_http_akamai_g2o_loc_conf_t;

static ngx_int_t ngx_http_akamai_g2o_handler(ngx_http_request_t *r);

static char *ngx_http_akamai_g2o_signature(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_akamai_g2o_hashmethod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_akamai_g2o_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_akamai_g2o_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_akamai_g2o_init(ngx_conf_t *cf);

void base64_signature_of_data(ngx_http_request_t *r, ngx_str_t data, ngx_str_t key, u_char *signature);
void binary_to_base64(unsigned char *md, unsigned int md_len, u_char *base64_out);
int try_get_auth_data_fields(ngx_str_t data, u_int *version, u_int *time, ngx_str_t *nonce);

static ngx_conf_post_handler_pt  ngx_http_akamai_g2o_signature_p =
    ngx_http_akamai_g2o_signature;

static ngx_command_t  ngx_http_akamai_g2o_commands[] = {
    { ngx_string("g2o"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, enable),
      NULL },

    { ngx_string("accesskey_hashmethod"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_akamai_g2o_hashmethod,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("accesskey_signature"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, signature),
      &ngx_http_akamai_g2o_signature_p },

    { ngx_string("accesskey_arg"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_akamai_g2o_loc_conf_t, arg),
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

      ngx_null_command
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

void get_data_and_sign_from_request_headers(ngx_http_request_t *r, ngx_str_t *header_data, ngx_str_t *header_sign) {
    ngx_list_t headers = r->headers_in.headers;
    ngx_list_part_t *part = &headers.part;
    ngx_table_elt_t* data = part->elts;
    ngx_table_elt_t header;

    unsigned int i;

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
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s: %s", header.key.data, header.value.data);

        if (ngx_strcasecmp((u_char*) "X-Akamai-G2O-Auth-Data", header.key.data) == 0) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "found X-Akamai-G2O-Auth-Data");
            *header_data = header.value;
        }
        if (ngx_strcasecmp((u_char*) "X-Akamai-G2O-Auth-Sign", header.key.data) == 0) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "found X-Akamai-G2O-Auth-Sign");
            *header_sign = header.value;
        }
    }
}

int check_has_g2o_headers(ngx_http_request_t *r, ngx_http_akamai_g2o_loc_conf_t  *alcf) {
    ngx_str_t header_data = ngx_null_string, header_sign = ngx_null_string;
    get_data_and_sign_from_request_headers(r, &header_data, &header_sign);

    if (header_data.data && header_sign.data) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "got both data and sign");

        if (!alcf->key.data) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "key not configured");
            return 0;
        }

        if (!alcf->nonce.data) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "nonce not configured");
            return 0;
        }

        // for base64 we need: ceiling(16 / 3) * 4 + 1 = 25 bytes
        // where 16 is MD5 digest length
        // + 1 for the string termination char
        // lets call it 40, just in case
        u_char signature [40];

        // signature is correct
        base64_signature_of_data(r, header_data, alcf->key, signature);

        u_int version, auth_time;
        ngx_str_t nonce;

        if (!try_get_auth_data_fields(header_data, &version, &auth_time, &nonce)) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "X-Akamai-G2O-Auth-Data not formatted correctly");
            return 0;
        }

        time_t current_time = ngx_time();

        // request using correct version of G2O
        if (version != 3) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "G2O version not 3");
            return 0;
        }

        // request not too far into the future
        if (auth_time > current_time + 30) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "request from too far into the future");
            return 0;
        }

        // request not too old
        if (auth_time < current_time - 30) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "request too old");
            return 0;
        }

        // nonce is correct
        if (ngx_strcmp(nonce.data, alcf->nonce.data)) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "nonce incorrect");
            return 0;
        }

        if (ngx_strncmp(header_sign.data, signature, header_sign.len)) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "signature incorrect, expected '%s' got '%s'", signature, header_sign.data);
            return 0;
        }

        // request past all checks, content is good to go!
        return 1;
    } else {
        return 0;
    }
}

void base64_signature_of_data(ngx_http_request_t *r, ngx_str_t data, ngx_str_t key, u_char *signature) {
    unsigned char md [EVP_MAX_MD_SIZE];
    unsigned int md_len;
    HMAC_CTX hmac;

    HMAC_Init(&hmac, key.data, key.len, EVP_md5());
    HMAC_Update(&hmac, data.data, data.len);
    HMAC_Update(&hmac, r->uri.data, r->uri.len);
    HMAC_Final(&hmac, md, &md_len);

    binary_to_base64(md, md_len, signature);
}

int try_get_auth_data_fields(ngx_str_t data, u_int *version, u_int *time, ngx_str_t *nonce) {
    char *version_field = strtok((char*) data.data, ", ");
    if (!version_field)
        return 0;
    char *ghost_ip_field = strtok(NULL, ", ");
    if (!ghost_ip_field)
        return 0;
    char *client_ip_field = strtok(NULL, ", ");
    if (!client_ip_field)
        return 0;
    char *time_field = strtok(NULL, ", ");
    if (!time_field)
        return 0;
    char *unique_id_field = strtok(NULL, ", ");
    if (!unique_id_field)
        return 0;
    char *nonce_field = strtok(NULL, ", ");
    if (!nonce_field)
        return 0;

    *version = atoi(version_field);
    *time = atoi(time_field);
    nonce->data = (unsigned char*) nonce_field;
    nonce->len = strlen(nonce_field);

    return 1;
}

void binary_to_base64(unsigned char *md, unsigned int md_len, u_char *base64_out) {
    // this function taken from: https://github.com/anomalizer/ngx_aws_auth/blob/master/ngx_http_aws_auth.c

    int t;

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());  
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, md, md_len);
    t = BIO_flush(b64); /* read the value esle some gcc, throws error*/
    BUF_MEM *bptr; 
    BIO_get_mem_ptr(b64, &bptr);

    ngx_memcpy((void*) base64_out, (void*) (bptr->data), (size_t) bptr->length-1);
    base64_out[bptr->length-1]='\0';

    BIO_free_all(b64);
}

static ngx_int_t
ngx_http_akamai_g2o_handler(ngx_http_request_t *r)
{
    ngx_http_akamai_g2o_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_akamai_g2o_module);

    if (!alcf->enable) {
        return NGX_OK;
    }

    if (check_has_g2o_headers(r, alcf)) {
        return NGX_OK;
    } else {
        return NGX_HTTP_FORBIDDEN;
    }
}

static char *
ngx_http_akamai_g2o_compile_signature(ngx_conf_t *cf, ngx_http_akamai_g2o_loc_conf_t *alcf)
{

    ngx_http_script_compile_t   sc;
    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &alcf->signature;
    sc.lengths = &alcf->signature_lengths;
    sc.values = &alcf->signature_values;
    sc.variables = ngx_http_script_variables_count(&alcf->signature);;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_akamai_g2o_signature(ngx_conf_t *cf, void *post, void *data)
{
    ngx_http_akamai_g2o_loc_conf_t *alcf =
	    ngx_http_conf_get_module_loc_conf(cf, ngx_http_akamai_g2o_module);

    return ngx_http_akamai_g2o_compile_signature(cf, alcf);
}

static char *
ngx_http_akamai_g2o_hashmethod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *d = cf->args->elts;
    ngx_http_akamai_g2o_loc_conf_t *alcf = conf;

    if ( (d[1].len == 3 ) && (ngx_strncmp(d[1].data,"md5",3) == 0) ) {
        alcf->hashmethod = NGX_ACCESSKEY_MD5;
    } else if ( (d[1].len == 4) && (ngx_strncmp(d[1].data,"sha1",4) == 0) ){
        alcf->hashmethod = NGX_ACCESSKEY_SHA1;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "accesskey_hashmethod should be md5 or sha1, not \"%V\"", d+1);
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
    conf->enable = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_http_akamai_g2o_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_akamai_g2o_loc_conf_t  *prev = parent;
    ngx_http_akamai_g2o_loc_conf_t  *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->hashmethod, prev->hashmethod, NGX_ACCESSKEY_MD5);
    ngx_conf_merge_str_value(conf->arg, prev->arg, "key");
    ngx_conf_merge_str_value(conf->signature,prev->signature,"$remote_addr");
    return ngx_http_akamai_g2o_compile_signature(cf, conf);
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
