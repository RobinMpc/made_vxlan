#include <stdio.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <math.h>
#include <string.h>
#include "neutron.h"

#define MAC 0
#define IP 1
#define ICMP 2
#define VXLAN 3
//typedef struct sockaddr* saddrp;

typedef struct message {
    uint8_t *message_hdr;
    int message_len;
    int message_type;
} MESSAGE;

typedef struct vxlan_header
{
    u_int16_t flags;
    u_int16_t gpid;
    char vni[3];
    u_int8_t reserved;
} VXAN_HEADER;

unsigned short cal_chksum(unsigned short *addr,int len)
{
    int nleft=len;
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;

    /*把ICMP报头二进制数据以2字节为单位累加起来*/
    while(nleft>1)
    {
        sum+=*w++;
        nleft-=2;
    }
    /*若ICMP报头为奇数个字节，会剩下最后一字节。
      把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
    if( nleft==1)
    {
        *(unsigned char *)(&answer)=*(unsigned char *)w;
        sum+=answer;
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return answer;
}

void icmp_pack(struct icmp* icmphdr, int seq, int length)
{
    unsigned short check_sum;

    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_seq = seq;
    icmphdr->icmp_id = 0x0000;
    check_sum = cal_chksum((unsigned short*)icmphdr, length);
    icmphdr->icmp_cksum = check_sum;
}


MESSAGE* icmp_made()
{
    char *send_buf = (char*) malloc (sizeof(char) * 8);
    MESSAGE *msg = (MESSAGE *)malloc(sizeof(MESSAGE));
    
    icmp_pack((struct icmp*)send_buf, 0, 8);
    msg->message_type = ICMP;
    msg->message_hdr = send_buf;
    msg->message_len = 8;
    
    return msg;
}

void l3ip_pack(struct iphdr *iphdr, int saddr[], int daddr[])
{
    int i, y = 24;
    unsigned short check_sum;
    long _saddr = 0, _daddr = 0;
    
    iphdr->ihl = 5;
    iphdr->version = 4;
    iphdr->tos = 0;
    iphdr->tot_len = 28;
    iphdr->tot_len = htons(iphdr->tot_len);
    iphdr->id = 1;
    iphdr->id = htons(iphdr->id);
    iphdr->frag_off = 0;
    iphdr->ttl = 64;
    iphdr->protocol = 1;
    iphdr->check = 0;
    
    for(i = 0; i < 4; i++)
    {
        _saddr = _saddr + saddr[i] * pow(2, y);
        y = y - 8;
    }
    iphdr->saddr = _saddr;
    _saddr = htonl(iphdr->saddr);;
    iphdr->saddr = _saddr;
    y = 24;

    for(i = 0; i < 4; i++)
    {
        _daddr = _daddr + daddr[i] * (int)pow(2, y);
        y = y - 8;
    }
    iphdr->daddr = _daddr;
    iphdr->daddr = htonl(iphdr->daddr);
    check_sum = cal_chksum((unsigned short*)iphdr, 20);
    iphdr->check = check_sum;
    
}

MESSAGE* l3ip_made(int s_addr[], int d_addr[])
{
    char *send_buf = (char*) malloc (sizeof(char) * 20);
    MESSAGE *msg = (MESSAGE *)malloc(sizeof(MESSAGE));
    l3ip_pack((struct iphdr*)send_buf, s_addr, d_addr);
    msg->message_type = IP;
    msg->message_hdr = send_buf;
    msg->message_len = 20;
    return msg;
}



void mac_pack(struct ether_header *mac_hdr, char smac[], char dmac[])
{
    int i = 0;

    for(i = 0; i < ETH_ALEN; i++)
    {
        mac_hdr->ether_dhost[i] = dmac[i];
        mac_hdr->ether_shost[i] = smac[i];
    }
    mac_hdr->ether_type = 0x0800;
    mac_hdr->ether_type = htons(mac_hdr->ether_type);
}

MESSAGE* mac_made(char s_addr[], char d_addr[])
{
    char *send_buf = (char*)malloc(sizeof(char) * 14);
    MESSAGE *msg = (MESSAGE *)malloc(sizeof(MESSAGE));
    mac_pack((struct ether_header*)send_buf, s_addr, d_addr);
    msg->message_type = MAC;
    msg->message_hdr = send_buf;
    msg->message_len = 14;
    return msg;
}

void vxlan_pack(VXAN_HEADER *vxlan_hdr, int vni)
{
    char *vni_addr = (char*)&vni;
    vxlan_hdr->flags = 0x0800;
    vxlan_hdr->flags = htons(vxlan_hdr->flags);
    vxlan_hdr->gpid = 0;
    vxlan_hdr->gpid = htons(vxlan_hdr->gpid);
    vxlan_hdr->vni[0] = *(vni_addr + 2);
    vxlan_hdr->vni[1] = *(vni_addr + 1);
    vxlan_hdr->vni[2] = *vni_addr;
    vxlan_hdr->reserved = 0;
}

MESSAGE* vxlan_made(int vni)
{
    char *send_buf = (char*) malloc (sizeof(char) * 8);
    MESSAGE *msg = (MESSAGE *)malloc(sizeof(MESSAGE));
    vxlan_pack((VXAN_HEADER*)send_buf, vni);
    msg->message_type = VXLAN;
    msg->message_hdr = send_buf;
    msg->message_len = 8;
    return msg;
}


int* ip_tran(char *ip)
{
    char *p;
    char ip_arr[15];
    int *_ip = (int*)malloc(sizeof(int)*4);
    int i = 0;
    memset(ip_arr, '\0', 15);
    strncpy(ip_arr, ip, strlen(ip));
    p = strtok(ip_arr, ".");
    _ip[i] = atoi(p);
    while(p)
    {
        i++;
        p = strtok(NULL, ".");
        if(p){
            _ip[i] = atoi(p);        
        }
    }
    return _ip;
}

int str_2_hex(char *str) {
    int num = 0,i;
    for (i = 0; i < 2; i++) {
        num*=16;
        if ( *str>='0' && *str<='9' ) num+=*str-'0';
        else if ( *str>='a' && *str<='f' ) num+=*str-'a'+10;
        else if ( *str>='A' && *str<='F' ) num+=*str-'A'+10;
        str++;
    }
    return num;
}

char* mac_tran(char *mac)
{
    int i = 0;
    char mac_arr[20], *p;
    char **_mac = (char**)malloc(sizeof(char*) * 6);
    char *result = (char*)malloc(sizeof(char) * 6);

    memset(mac_arr, '\0', 20);
    strncpy(mac_arr, mac, strlen(mac));
    p = strtok(mac_arr, ":");
    _mac[i] = p;
    while(p)
    {
        i++;
        p = strtok(NULL, ":");
        if(p)
            _mac[i] = p;        
    }
    
    for(i = 0; i < 6; i++)
    {
        result[i] = str_2_hex(_mac[i]);
    }
    
    return result;
}

MESSAGE* made_payload(char *inner_sip, char *inner_dip, int vni)
{
    /*
    第一步,构造icmp报文
    */
    MESSAGE *icmp_msg = icmp_made();
    /*
    第二步,构造ip报文头部
    构造IP报文头部的参数为整型数组，用来保存源IP和目的IP
    所以先将字符串形式的IP地址转化为整型数组
    */
    int *int_inner_sip = ip_tran(inner_sip);
    int *int_inner_dip = ip_tran(inner_dip);
    MESSAGE *ip_msg = l3ip_made(int_inner_sip, int_inner_dip);
    /*
    第三步,构造mac数据帧头部
    源mac: 11:22:33:44:55:66 写死
    目的mac: ee:ff:ff:ff:ff:ff 写死
    */
    char *_s_mac = mac_tran("11:22:33:44:55:66");
    char *_d_mac = mac_tran("ee:ff:ff:ff:ff:ff");
    MESSAGE *mac_msg = mac_made(_s_mac, _d_mac);
     /*
    第四步,构造vxlan头部
    */
    MESSAGE *vxlan_msg = vxlan_made(vni);

    int len = icmp_msg->message_len + ip_msg->message_len + mac_msg->message_len + vxlan_msg->message_len;
    uint8_t * buf = (uint8_t *)malloc(sizeof(uint8_t) * (len + 2));
    memset(buf, 0, sizeof(uint8_t) * (len + 2));
    uint8_t * index = buf; //定义一个索引指针
    /*
    最前面的是vxlan头部
    */
    memcpy(index, vxlan_msg->message_hdr, sizeof(uint8_t) * vxlan_msg->message_len);
    index = index + vxlan_msg->message_len;
    /*
    然后是mac数据帧头部
    */
    memcpy(index, mac_msg->message_hdr, sizeof(uint8_t) * mac_msg->message_len);
    index = index + mac_msg->message_len;
    /*
    接着是IP报文头部
    */
    memcpy(index, ip_msg->message_hdr, sizeof(uint8_t) * ip_msg->message_len);
    index = index + ip_msg->message_len;
    /*
    最后是icmp报文
    */
    memcpy(index, icmp_msg->message_hdr, sizeof(uint8_t) * icmp_msg->message_len);
    
    MESSAGE *payload = (MESSAGE *)malloc(sizeof(MESSAGE));
    payload->message_hdr = buf;
    payload->message_len = len;
    
    free(icmp_msg);
    free(ip_msg);
    free(mac_msg);
    free(vxlan_msg);
    
    return payload;
}


