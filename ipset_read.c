//
// Nginx http ipset black/whitelist access module by Vasfed
// 
// routines for ipset access
//

#include "ipset_read.h"

#include <sys/types.h> 
#include <sys/socket.h>	
#include <arpa/inet.h>

#include <errno.h>
#include <string.h>
#include <unistd.h> // close etc.

#define typename typename_ // for c++ compatibility
//TODO: include this header from somewhere in system...
#include "ip_set.h"
#undef typename



char* altered_str_error(){
  switch(errno){
    case EPERM: return "Missing capability(or not allowed)";
    case EBADF: return "Invalid socket option";
    case EINVAL: return "Size mismatch for expected socket data";
    case ENOMEM: return "Not enough memory";
    case EFAULT: return "Failed to copy data";
    case EPROTO: return "ipset kernel/userspace version mismatch";
    case EBADMSG: return "Unknown ipset command";
    case ENOENT: return "Unknown ipset";
    case EAGAIN: return "IpSets are busy, try again later";
    case ERANGE: return "IP/port/element is outside of the set or set is full";
    case EEXIST: return "Set specified as element does not exist";
    case EBUSY: return "Set is in use, operation not permitted";
    case ENOPROTOOPT: return "No module in kernel";
    default: return strerror(errno);
  }
}

static int kernel_ipset_getcmd(void *data, socklen_t * size);

static int g_raw_socket = -1;
static int g_protocol_version = 0;

//do not call twice (but call for each fork?)
int ipset_read_init(char** errorstr){
  g_raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (g_raw_socket < 0){
	  if(errorstr)
      *errorstr = strerror(errno);
    return 0;
	}
	
	struct ip_set_req_version req_version;
	socklen_t size = sizeof(struct ip_set_req_version);
	req_version.op = IP_SET_OP_VERSION;

	if (!kernel_ipset_getcmd(&req_version, &size)){
    ipset_read_free();
    if(errorstr)
	    *errorstr = "Couldn't verify ipset kernel module version";
    return 0;
	}

	if (!(req_version.version == IP_SET_PROTOCOL_VERSION || req_version.version == IP_SET_PROTOCOL_UNALIGNED)){
    ipset_read_free();
    if(errorstr)
      *errorstr = "ipset kernel module protocol version mismatch";
    return 0;
	}

	g_protocol_version = req_version.version;	
  return 1;
}

static int check_init(char** errorstr){
  if(g_raw_socket < 0){
    return ipset_read_init(errorstr);    
  }
  return 1;
}

void ipset_read_free(void){
  if(g_raw_socket){
    int tmp = g_raw_socket;
    g_raw_socket = -1;
    close(tmp);
  }
}

static int kernel_ipset_getcmd(void *data, socklen_t * size){
  int res = getsockopt(g_raw_socket, SOL_IP, SO_IP_SET, data, size);
  if (res != 0)
    return 0;
  return 1;
}

static int kernel_ipset_setcmd(void *data, socklen_t size){
  int res = setsockopt(g_raw_socket, SOL_IP, SO_IP_SET, data, size);
  if (res != 0) {
		if (errno == EEXIST)
			return -1; // no element is ok for most cmds
		else
			return -2; // more fatal error
	}

	return 0; //all ok
}

ipset_handle_t ipset_read_get_handle(u_char* set_name, char** errorstr){
  if(!check_init(errorstr))
    return -1;
  
  struct ip_set_req_adt_get req_adt_get;
  socklen_t size = sizeof(req_adt_get);

  req_adt_get.op = IP_SET_OP_ADT_GET;
  req_adt_get.version = g_protocol_version;
  strncpy(req_adt_get.set.name, (char*)set_name, IP_SET_MAXNAMELEN);

  if(kernel_ipset_getcmd((void *) &req_adt_get, &size))
    return req_adt_get.set.index;

  if(errorstr)
    *errorstr = altered_str_error();
  return -1;
}

ipset_read_result_t ipset_read_check_ip(ipset_handle_t set, struct sockaddr_in* addr, char** err){
  if(!check_init(err))
    return IPS_FAIL;
    
  //some kind of hack to save a malloc call...
  struct {
    struct ip_set_req_adt req_adt;
    ip_set_ip_t ip;
  } cmd;  

  //test cmd is 'add, but not commit', issued like an ordinary add/delete
	cmd.req_adt.op = IP_SET_OP_TEST_IP;
	cmd.req_adt.index = set;
  cmd.ip = ntohl(addr->sin_addr.s_addr);
  
  int res = kernel_ipset_setcmd(&cmd, sizeof(cmd));
  if(res == -1)
    return IPS_IN_SET;
  if(res == 0)
    return IPS_NOT_IN_SET;
  if(err)
    *err = altered_str_error();
  return IPS_FAIL;
}
