#include "system.h"

#include "avl_tree.h"
#include "local_subnet.h"

#include <pthread.h>
#include <stdlib.h>

pthread_mutex_t tree_lock;
int local_subnet_lock_inited = 0;

avl_tree_t *local_subnet_tree;

static int my_maskcmp(const void *va, const void *vb, int masklen) {
    int i, m, result;
    const char *a = va;
    const char *b = vb;
    
    for(m = masklen, i = 0; m >= 8; m -= 8, i++) {
        result = a[i] - b[i];
        if(result)
            return result;
    }
    
    if(m)
        return (a[i] & (0x100 - (1 << (8 - m)))) -
        (b[i] & (0x100 - (1 << (8 - m))));
    
    return 0;
}

int local_subnet_compare(const local_subnet_t *a, const local_subnet_t *b)
{
    int result;
    
    result = b->net.prefixlength - a->net.prefixlength;
    
    if(result)
        return result;
    
    result = memcmp(&a->net.address, &b->net.address, sizeof(local_ipv4_t));
    
    return result;
}

local_subnet_t *new_local_subnet(void) {
    return calloc(1, sizeof(local_subnet_t));
}

void free_local_subnet(local_subnet_t *sn) {
    free(sn);
}

void init_local_subnet_tree()
{
    if (!local_subnet_lock_inited)
    {
        pthread_mutex_init(&tree_lock, NULL);
        local_subnet_lock_inited = 1;
    }
    local_subnet_tree = avl_alloc_tree((avl_compare_t) local_subnet_compare, (avl_action_t) free_local_subnet);
}

void local_subnet_tree_lock()
{
    pthread_mutex_lock(&tree_lock);
}

void local_subnet_tree_unlock()
{
    pthread_mutex_unlock(&tree_lock);
}

void free_local_subnet_tree()
{
    avl_delete_tree(local_subnet_tree);
    local_subnet_tree = NULL;
}

local_subnet_t* lookup_local_subnet_ipv4(const local_ipv4_t *address)
{
    local_subnet_t* r = NULL;
    local_subnet_t* p = NULL;
    avl_node_t *n = NULL;
    for( n = local_subnet_tree->head; n != NULL; n = n->next)
    {
        p = n->data;
        if(!my_maskcmp(address, &p->net.address, p->net.prefixlength)) {
            r = p;
            break;
        }
    }
    return r;
}

void local_subnet_add(local_ipv4_t *sn_ip, int prefixlength, local_ipv4_t *vip)
{
    local_subnet_t* r = new_local_subnet();
    memcpy(r->net.address.x, sn_ip->x, sizeof(sn_ip->x));
    r->net.prefixlength = prefixlength;
    avl_insert(local_subnet_tree, r);
}

void local_subnet_del(local_subnet_t *del)
{
    avl_delete(local_subnet_tree, del);
}

void local_subnet_update_add(local_ipv4_t *sn_ip, int prefixlength, local_ipv4_t *vip)
{
    local_subnet_t* r = NULL;
    r = lookup_local_subnet_ipv4(sn_ip);
    if (!r)
    {
        local_subnet_add(sn_ip, prefixlength, vip);
    }
    memcpy(r->vip.x, vip->x, sizeof(vip->x));
}

void local_subnet_update_del(local_ipv4_t *sn_ip)
{
    local_subnet_t* r = NULL;
    r = lookup_local_subnet_ipv4(sn_ip);
    if (r)
    {
        local_subnet_del(r);
    }
}

static int str2ipv4(char *ip, local_ipv4_t *sip)
{
    int ret = -1;
    unsigned int temp1;
    unsigned int temp2;
    unsigned int temp3;
    unsigned int temp4;
    int scan_ret = sscanf(ip, "%u.%u.%u.%u", &temp1, &temp2, &temp3, &temp4);
    if (scan_ret == 4)
    {
        sip->x[0] = (uint8_t)(temp1 & 0xff);
        sip->x[1] = (uint8_t)(temp2 & 0xff);
        sip->x[2] = (uint8_t)(temp3 & 0xff);
        sip->x[3] = (uint8_t)(temp4 & 0xff);
        ret = 0;
    }
    return ret;
}

static int str2subnet(char* subnet, local_ipv4_t* sip, int* prefixlength)
{
    int ret = -1;
    char *ip_str = subnet;
    char *masklen_str = strchr(subnet, '/');
    if (masklen_str)
    {
        *masklen_str = 0;
        masklen_str++;
        str2ipv4(ip_str, sip);
        *prefixlength = atoi(masklen_str);
    }
    return ret;
}

void local_subnet_str_add(char *subnet_str, char *vip_str)
{
    local_ipv4_t vip;
    local_ipv4_t sn_ip;
    int prefixlength;
    if (!local_subnet_tree)
    {
        init_local_subnet_tree();
    }
    int subnet_ret = str2subnet(subnet_str, &sn_ip, &prefixlength);
    int vip_ret = str2ipv4(vip_str, &vip);
    if (subnet_ret == 0 && vip_ret == 0)
    {
        local_subnet_update_add(&sn_ip, prefixlength, &vip);
    }
}

void local_subnet_str_del(char *subnet_str)
{
    local_ipv4_t sn_ip;
    int prefixlength;
    int subnet_ret = str2subnet(subnet_str, &sn_ip, &prefixlength);
    if (!local_subnet_tree)
    {
        init_local_subnet_tree();
    }
    if (subnet_ret == 0)
    {
        local_subnet_update_del(&sn_ip);
    }
}
