//
// Nginx http ipset black/whitelist access module by Vasfed
//
// Usage:
// place a "blacklist 'ipset_name';" config option in http or a virtual host context
// there can be only one list, its color is determined by cmd name.
//
// blacklist => deny request if ip is in list
// whitelist => deny everything except in list
//
//
// note: restart nginx if ipset is renamed/moved/deleted etc.
// no need for restart on ipset content change (that's what this module is for :) )
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ipset_read.h"




static char*     ngx_http_ipset_access_list_conf      (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void*     ngx_http_ipset_access_create_srv_conf(ngx_conf_t *cf);
static char*     ngx_http_ipset_access_merge_srv_conf (ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_ipset_access_init           (ngx_conf_t *cf);
static ngx_int_t ngx_http_ipset_on_init_process       (ngx_cycle_t *cycle);
//-------------------------------------------------------------------------------------------------------------
//NGINX module ABI:

static ngx_command_t  ngx_http_ipset_access_commands[] = {

    { ngx_string("blacklist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF // configurable per virtual server
      | NGX_CONF_TAKE1,
      ngx_http_ipset_access_list_conf,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whitelist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF 
      | NGX_CONF_TAKE1,
      ngx_http_ipset_access_list_conf,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_ipset_blacklist_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ipset_access_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ipset_access_create_srv_conf, /* create server configuration */
    ngx_http_ipset_access_merge_srv_conf,  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ipset_blacklist = {
    NGX_MODULE_V1,
    &ngx_http_ipset_blacklist_module_ctx,  /* module context */
    ngx_http_ipset_access_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_ipset_on_init_process,        /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

//-------------------------------------------------------------------------------------------------------------
//Config-related:

typedef struct {
  enum {
    e_mode_not_configured = 0,
    e_mode_off,
    e_mode_blacklist,
    e_mode_whitelist
    } mode;
  ipset_handle_t ipset_handle;
} ngx_http_ipset_access_server_conf_t;



static void* ngx_http_ipset_access_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ipset_access_server_conf_t  *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipset_access_server_conf_t));
    if (conf == NULL) {
        //indicate some error?
        return NULL;
    }

    return conf;
}

static char* ngx_http_ipset_access_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ipset_access_server_conf_t  *prev = parent;
    ngx_http_ipset_access_server_conf_t  *conf = child;

    if (!conf->mode) {
        conf->mode = prev->mode;
        conf->ipset_handle = prev->ipset_handle;
    }

    return NGX_CONF_OK;
}

static char* ngx_http_ipset_access_list_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *p_conf)
{
    //alcf= conf
    ngx_http_ipset_access_server_conf_t *conf = p_conf;
    ngx_str_t *value = cf->args->elts;

    if (value[1].len == 3 && !ngx_strcmp(value[1].data, "off")) {
      conf->mode = e_mode_off;
      return NGX_CONF_OK;
    }

    //get ipset handle from kernel:
    char* strerr = "no error returned";
    conf->ipset_handle = ipset_read_get_handle(value[1].data, &strerr);
    if(conf->ipset_handle == -1){
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "cannot get ipset \"%V\" from kernel, check nginx to be running as root (%s)", &value[1], strerr);
      return NGX_CONF_ERROR;      
    }
    
    //check if cmd was 'whitelist' or 'blacklist'
    conf->mode = value[0].data[0] == 'b' ? e_mode_blacklist : e_mode_whitelist;


    //debug
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "configured for ipset %V", &value[1]);


    //test here:
    struct sockaddr_in addr;
    int res = IPS_FAIL;
    char* err = "cannot convert test ip to int";
  	if (inet_aton("127.0.0.1", &addr.sin_addr)) {
      err = "no err returned";
      res = ipset_read_check_ip(conf->ipset_handle, (struct sockaddr_in *)&addr, &err);      
  	}  

    if(res == IPS_FAIL){
      ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to test read ipset \"%V\", check nginx to be running all processes as root: %s", &value[1], err);
      return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

//-------------------------------------------------------------------------------------------------------------
static ngx_int_t ngx_http_ipset_on_init_process(ngx_cycle_t *cycle){  
  
  if(geteuid() != 0) {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "To run ipsets all worker threads need to be run as root (check config)");
    return NGX_ERROR;
  }
  
  if(1){
    //do we need re-init?
    return NGX_OK;
  }
  
  char* err = "no err returned";
  if(!ipset_read_init(&err)){
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cannot init ipset client: %s", err);
    return NGX_ERROR;
  }
  return NGX_OK;
}

static ngx_int_t ngx_http_ipset_access_handler(ngx_http_request_t *r)
{
    ngx_http_ipset_access_server_conf_t  *conf = ngx_http_get_module_srv_conf(r, ngx_http_ipset_blacklist);

    if (r->connection->sockaddr->sa_family == AF_INET) {
      char* err = "no err returned";
      int res = ipset_read_check_ip(conf->ipset_handle, (struct sockaddr_in*) r->connection->sockaddr, &err);

      if(res == IPS_FAIL){
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "failed to read white/blacklist: %s", err);
      }
      
      
      if((conf->mode == e_mode_whitelist && (res == IPS_NOT_IN_SET || res == IPS_FAIL)) ||
         (conf->mode == e_mode_blacklist && res == IPS_IN_SET)){
        
        //TODO: remove in production?
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access for %s forbidden by black/whitelist", inet_ntoa(((struct sockaddr_in*)r->connection->sockaddr)->sin_addr));

        return NGX_HTTP_FORBIDDEN;
      }

      return NGX_OK;  
    }

    #if (NGX_HAVE_INET6)
      //FIXME: IPv6 support? ipsets do not seem to support it
      #warning IPv6 is not supported by ipset_module, IPv6 requests will not be filtered
    #endif

    return NGX_DECLINED; // we have nothing to do with this request => pass to next handler
}


#define checked_array_push(arr, elem) { h = ngx_array_push(&arr); if (h == NULL){ return NGX_ERROR;} *h = elem; }
//extern ngx_module_t  ngx_core_module;

static ngx_int_t ngx_http_ipset_access_init(ngx_conf_t *cf)
{
    //check conf:
    ngx_core_conf_t* ccf;
    ccf = (ngx_core_conf_t *) NULL; //ngx_get_conf(???, ngx_core_module);
    if(geteuid() != 0 || (ccf && (ccf->user == (uid_t) NGX_CONF_UNSET_UINT || ccf->user != 0))){
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "To run ipsets all worker threads need to be run as root (add 'user root' to core config, current is %d)", ccf->user);
      return NGX_ERROR; 
    }
  

    //install handler
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    checked_array_push(cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers, ngx_http_ipset_access_handler);

    return NGX_OK;
}
