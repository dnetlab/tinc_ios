#ifndef _SRC_LOCAL_SUBNET_H_
#define _SRC_LOCAL_SUBNET_H_

#include <stdio.h>
#include <stdint.h>

typedef struct local_ipv4_s {
    uint8_t x[4];
}local_ipv4_t;

typedef struct local_subnet_ipv4_s {
    local_ipv4_t address;
    int prefixlength;
} local_subnet_ipv4_t;

typedef struct local_subnet_s
{
    local_subnet_ipv4_t net;
    local_ipv4_t		vip;
}local_subnet_t;

void init_local_subnet_tree();
void free_local_subnet_tree();

void local_subnet_tree_lock();
void local_subnet_tree_unlock();

local_subnet_t* lookup_local_subnet_ipv4(const local_ipv4_t *address);

void local_subnet_update_add(local_ipv4_t *sn_ip, int prefixlength, local_ipv4_t *vip);
void local_subnet_update_del(local_ipv4_t *sn_ip);

void local_subnet_str_add(char *subnet_str, char *vip_str);
void local_subnet_str_del(char *subnet_str);
#endif
