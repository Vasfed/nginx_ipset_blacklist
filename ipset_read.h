#ifndef __IPSET_READ_HEADER_FILE_INCLUDED
#define __IPSET_READ_HEADER_FILE_INCLUDED

#include <netinet/in.h>

typedef enum {
 IPS_FAIL = -1,
 IPS_NOT_IN_SET = 0,
 IPS_IN_SET = 1
} ipset_read_result_t;

typedef int ipset_handle_t;

int ipset_read_init(char** errorstr);
void ipset_read_free(void);

ipset_handle_t ipset_read_get_handle(u_char* set_name, char** errorstr);
ipset_read_result_t ipset_read_check_ip(ipset_handle_t set, struct sockaddr_in* ip, char** err);


#endif //#ifndef __IPSET_READ_HEADER_FILE_INCLUDED