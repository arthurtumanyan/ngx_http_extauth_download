/* 
 * Copyright (C) 2013 Arthur Tumanyan
 * Copyright (C) 2013 Netangels, LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mhash.h>
#include <openssl/md5.h>
#include <ctype.h>
#include <libmemcached/memcached.h>

#define FOLDER_MODE 0
#define FILE_MODE 1
#define PATH_SZ 1024

typedef struct {
    const char *timestamp;
    const char *md5;
    const char *path;
    const char *real_path;
    int path_len;
    int path_to_hash_len;
} ngx_http_extauth_download_split_uri_t;

memcached_server_st *servers = NULL;
memcached_st *memc = NULL;
memcached_return rc;
size_t memcache_value_len = 32;
uint32_t memcache_value_flags = 0;
/*
 * Forward declarations
 */
static ngx_int_t ngx_http_extauth_download_split_uri(ngx_http_request_t*, ngx_http_extauth_download_split_uri_t*);
static ngx_int_t ngx_http_extauth_download_check_hash(ngx_http_request_t*, ngx_http_extauth_download_split_uri_t*, ngx_str_t*);
static void * ngx_http_extauth_download_create_loc_conf(ngx_conf_t*);
static char * ngx_http_extauth_download_merge_loc_conf(ngx_conf_t*, void*, void*);
static ngx_int_t ngx_http_extauth_download_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_extauth_download_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static char * ngx_conf_set_path_mode(ngx_conf_t*, ngx_command_t*, void*);

/*
 * Structures
 */

/*

 */

typedef struct {
    ngx_flag_t enable;
    ngx_flag_t path_mode;
    ngx_str_t keyserver_ip;
    ngx_int_t keyserver_port;
} ngx_http_extauth_download_loc_conf_t;

static ngx_command_t ngx_http_extauth_download_commands[] = {
    {
        ngx_string("extauth_download"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_extauth_download_loc_conf_t, enable),
        NULL
    },
    {
        ngx_string("extauth_download_path_mode"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_path_mode,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_extauth_download_loc_conf_t, path_mode),
        NULL
    }
    ,
    {
        ngx_string("extauth_download_keyserver_ip"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_extauth_download_loc_conf_t, keyserver_ip),
        NULL
    }
    ,
    {
        ngx_string("extauth_download_keyserver_port"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_extauth_download_loc_conf_t, keyserver_port),
        NULL
    }
};

static ngx_http_module_t ngx_http_extauth_download_module_ctx = {
    ngx_http_extauth_download_add_variables,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_extauth_download_create_loc_conf,
    ngx_http_extauth_download_merge_loc_conf
};

ngx_module_t ngx_http_extauth_download_module = {
    NGX_MODULE_V1,
    &ngx_http_extauth_download_module_ctx,
    ngx_http_extauth_download_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_str_t ngx_http_extauth_download = ngx_string("extauth_download");

static ngx_int_t ngx_http_extauth_download_add_variables(ngx_conf_t *cf) {
    ngx_http_variable_t *var;

    var = ngx_http_add_variable(cf, &ngx_http_extauth_download, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_extauth_download_variable;

    return NGX_OK;
}

/*
 Functions
 */

static ngx_int_t ngx_http_extauth_download_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    unsigned timestamp;
    unsigned remaining_time = 0;
    ngx_http_extauth_download_loc_conf_t *sdc;
    ngx_http_extauth_download_split_uri_t sdsu;
    ngx_str_t secret;
    char md5str[34];
    memset(md5str, '\0', 34);
    int value = 0;

    sdc = ngx_http_get_module_loc_conf(r, ngx_http_extauth_download_module);
    if (sdc->enable != 1) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: module not enabled");
        value = -3;
        goto finish;
    } else {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: module enabled");
    }

    if (NULL == memc) {
        memc = memcached_create(NULL);
        servers = memcached_server_list_append(servers, (const char *) sdc->keyserver_ip.data, sdc->keyserver_port, &rc);
        rc = memcached_server_push(memc, servers);
        if (rc == MEMCACHED_SUCCESS) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: added server successfully", 0);
        } else {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: couldn't add server: %s\n", memcached_strerror(memc, rc));
            value = -4;
            goto finish;
        }
    }
    if (ngx_http_extauth_download_split_uri(r, &sdsu) == NGX_ERROR) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: received an error from ngx_http_extauth_download_split_uri", 0);
        value = -3;
        goto finish;
    }

    if (sscanf(sdsu.timestamp, "%08X", &timestamp) != 1) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: error in timestamp hex-dec conversion", 0);
        value = -3;
        goto finish;
    }

    remaining_time = timestamp - (unsigned) time(NULL);
    if ((int) remaining_time <= 0) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: expired timestamp", 0);
        value = -1;
        goto finish;
    }

    // defining key
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: key = %s", sdsu.real_path);
    char * return_value = memcached_get(memc, sdsu.real_path, strlen(sdsu.real_path), &memcache_value_len, &memcache_value_flags, &rc);
    if (rc == MEMCACHED_SUCCESS) {
        secret.data = (u_char *) return_value;
        secret.len = sizeof (return_value) - 1;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: %s", memcached_strerror(memc, rc));
        value = -5;
        goto finish;
    }

    snprintf(md5str, 33, "%s", sdsu.md5);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: fetched_value = %s", return_value);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: md5hash_to_compare = %s", md5str);

    if (ngx_http_extauth_download_check_hash(r, &sdsu, &secret) != NGX_OK) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: bad hash", 0);
        value = -2;
        goto finish;
    }

finish:

    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    if (value == 0) {
        v->data = ngx_pcalloc(r->pool, sizeof (char) * 12);
        if (v->data == NULL) {
            return NGX_ERROR;
        }
        v->len = (int) sprintf((char *) v->data, "%i", remaining_time);
    } else {
        v->data = ngx_pcalloc(r->pool, sizeof (char) * 3);
        if (v->data == NULL) {
            return NGX_ERROR;
        }
        v->len = (int) sprintf((char*) v->data, "%i", value);
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_extauth_download_check_hash(ngx_http_request_t *r, ngx_http_extauth_download_split_uri_t *sdsu, ngx_str_t *secret) {
    if (memcmp(secret->data, sdsu->md5, 32) != 0) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void * ngx_http_extauth_download_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_extauth_download_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof (ngx_http_extauth_download_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->path_mode = NGX_CONF_UNSET;
    conf->keyserver_ip.data = NULL;
    conf->keyserver_ip.len = 0;
    conf->keyserver_port = 11211;

    return conf;
}

static char * ngx_http_extauth_download_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_extauth_download_loc_conf_t *prev = parent;
    ngx_http_extauth_download_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->path_mode, prev->path_mode, FOLDER_MODE);

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_extauth_download_split_uri(ngx_http_request_t *r, ngx_http_extauth_download_split_uri_t *sdsu) {
    int md5_len = 0;
    int tstamp_len = 0;
    int len = r->uri.len;
    char tmp_path[PATH_SZ];
    const char *uri = (char*) r->uri.data;
    memset(tmp_path, '\0', PATH_SZ);
    snprintf(tmp_path, PATH_SZ, "%s", uri);

    ngx_http_extauth_download_loc_conf_t *sdc = ngx_http_get_module_loc_conf(r, ngx_http_extauth_download_module);

    while (len && uri[--len] != '/')
        ++tstamp_len;
    if (tstamp_len != 8) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: timestamp size mismatch: %d", tstamp_len);
        return NGX_ERROR;
    }
    sdsu->timestamp = uri + len + 1;

    while (len && uri[--len] != '/')
        ++md5_len;
    if (md5_len != 32) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: hash size mismatch: %d", md5_len);
        return NGX_ERROR;
    }
    sdsu->md5 = uri + len + 1;

    const char s[2] = "/";
    char *token;
    char *new_path = malloc(PATH_SZ * sizeof (char));
    if (NULL == new_path) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: memory allocation error", 0);
        return NGX_ERROR;
    }
    memset(new_path, '\0', PATH_SZ);
    strcpy(new_path, (char *) "/");

    token = strtok((char *) tmp_path, s);
    if (NULL == token) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: null token", 0);
        return NGX_ERROR;
    }

    while (token != NULL && 32 != strlen(token)) {
        strcat(new_path, (char *) token);
        token = strtok(NULL, s);
        strcat(new_path, (char *) "/");
    }
    new_path[strlen(new_path) - 1] = '\0';
    sdsu->real_path = new_path;

    if (len == 0) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "extauth_download: bad path", 0);
        return NGX_ERROR;
    }

    sdsu->path = uri;
    sdsu->path_len = len;
    if (sdc->path_mode == FOLDER_MODE) {
        while (len && uri[--len] != '/');
    }
    sdsu->path_to_hash_len = len;

    return NGX_OK;
}

static char * ngx_conf_set_path_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *d = cf->args->elts;
    ngx_http_extauth_download_loc_conf_t *sdlc = conf;
    if ((d[1].len == 6) && (strncmp((char*) d[1].data, "folder", 6) == 0)) {
        sdlc->path_mode = FOLDER_MODE;
    } else if ((d[1].len == 4) && (strncmp((char*) d[1].data, "file", 4) == 0)) {
        sdlc->path_mode = FILE_MODE;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "extauth_download_path_mode should be folder or file", 0);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}