#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

// #include "ping.h"

#define DATA_SIZE 32

#define pri_debug printf
#define pri_error printf

typedef struct tag_icmp_header
{
    uint8_t  type;
    uint8_t  code;
    uint16_t check_sum;
    uint16_t id;
    uint16_t seq;
} icmp_header;

typedef struct tag_iphdr
{
    uint8_t        ip_head_verlen;
    uint8_t        ip_tos;
    unsigned short  ip_length;
    unsigned short  ip_id;
    unsigned short  ip_flags;
    uint8_t        ip_ttl;
    uint8_t        ip_protacol;
    unsigned short  ip_checksum;
    int             ip_source;
    int             ip_destination;
} ip_header;

unsigned short generation_checksum(unsigned short * buf, int size)
{
    unsigned long cksum = 0;
    while(size > 1)
    {
        cksum += *buf++;
        size -= sizeof(unsigned short);
    }

    if(size)
    {
        cksum += *buf++;
    }

    cksum =  (cksum>>16) + (cksum & 0xffff);
    cksum += (cksum>>16);

    return (unsigned short)(~cksum);
}

double get_time_interval(struct timeval * start, struct timeval * end)
{
    double interval;
    struct timeval tp;

    tp.tv_sec = end->tv_sec - start->tv_sec;
    tp.tv_usec = end->tv_usec - start->tv_usec;
    if(tp.tv_usec < 0)
    {
        tp.tv_sec -= 1;
        tp.tv_usec += 1000000;
    }

    interval = tp.tv_sec * 1000 + tp.tv_usec * 0.001;
    return interval;
}

int ping_host_ip(const char * domain)
{
    int i;
    int ret = -1;
    int client_fd;
    int size = 50 * 1024;
    struct timeval timeout;
    char * icmp;
    in_addr_t dest_ip;
    icmp_header * icmp_head;
    struct sockaddr_in dest_socket_addr;

    if(domain == NULL)
    {
        pri_debug("ping_host_ip domain is NULL!\n");
        return ret;
    }

    dest_ip = inet_addr(domain);
    if(dest_ip == INADDR_NONE)
    {
        struct hostent* p_hostent = gethostbyname(domain);
        if(p_hostent)
        {
            dest_ip = (*(in_addr_t*)p_hostent->h_addr);
        }
    }

    client_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (client_fd == -1)
    {
        pri_error("socket error: %s!\n", strerror(errno));
        return ret;
    }

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    if(setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)))
    {
        pri_error("setsocketopt SO_RCVTIMEO error!\n");
        return ret;
    }

    if(setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)))
    {
        pri_error("setsockopt SO_SNDTIMEO error!\n");
        return ret;
    }

    dest_socket_addr.sin_family = AF_INET;
    dest_socket_addr.sin_addr.s_addr = dest_ip;
    dest_socket_addr.sin_port = htons(0);
    memset(dest_socket_addr.sin_zero, 0, sizeof(dest_socket_addr.sin_zero));

    icmp = (char *)malloc(sizeof(icmp_header) + DATA_SIZE);
    memset(icmp, 0, sizeof(icmp_header) + DATA_SIZE);

    icmp_head = (icmp_header *)icmp;
    icmp_head->type = 8;
    icmp_head->code = 0;
    icmp_head->id = 1;

    // pri_debug("PING %s (%s).\n", domain, inet_ntoa(*((struct in_addr*)&dest_ip)));

    for(i = 0; i < 4; i++)
    {
        struct timeval start;
        struct timeval end;
        long result;
        struct sockaddr_in from;
        socklen_t from_packet_len;
        long read_length;
        char recv_buf[1024];

        icmp_head->seq = htons(i);
        icmp_head->check_sum = 0;
        icmp_head->check_sum = generation_checksum((unsigned short*)icmp,
            sizeof(icmp_header) + DATA_SIZE);
        gettimeofday(&start, NULL);
        result = sendto(client_fd, icmp, sizeof(icmp_header) +
            DATA_SIZE, 0, (struct sockaddr *)&dest_socket_addr,
            sizeof(dest_socket_addr));
        if(result == -1)
        {
            pri_debug("PING: sendto: Network is unreachable\n");
            continue;
        }

        from_packet_len = sizeof(from);
        memset(recv_buf, 0, sizeof(recv_buf));
        while(1)
        {
            read_length = recvfrom(client_fd, recv_buf, 1024, 0,
                (struct sockaddr*)&from, &from_packet_len);
            gettimeofday( &end, NULL );

            if(read_length != -1)
            {
                ip_header * recv_ip_header = (ip_header*)recv_buf;
                int ip_ttl = (int)recv_ip_header->ip_ttl;
                icmp_header * recv_icmp_header = (icmp_header *)(recv_buf +
                    (recv_ip_header->ip_head_verlen & 0x0F) * 4);

                if(recv_icmp_header->type != 0)
                {
                    pri_error("error type %d received, error code %d \n", recv_icmp_header->type, recv_icmp_header->code);
                    break;
                }

                if(recv_icmp_header->id != icmp_head->id)
                {
                    pri_error("some else's packet\n");
                    break;
                }

                if(read_length >= (sizeof(ip_header) +
                    sizeof(icmp_header) + DATA_SIZE))
                {
                    // pri_debug("%ld bytes from %s (%s): icmp_seq=%d ttl=%d time=%.2f ms\n",
                    //     read_length, domain, inet_ntoa(from.sin_addr), recv_icmp_header->seq / 256,
                    //     ip_ttl, get_time_interval(&start, &end));

                    ret = 0;
                    // 证明网络通畅，后续的包已经不许再需要验证
                    goto PING_EXIT;
                }

                break;
            }
            else
            {
                pri_error("receive data error!\n");
                break;
            }
        }
    }

PING_EXIT:
    if(NULL != icmp)
    {
        free(icmp);
        icmp = NULL;
    }

    if(client_fd != -1)
    {
        close(client_fd);
    }

    return ret;
}

void socket_set_timeout(int socket, uint32_t seconds, uint32_t usec)
{
    struct timeval tv;

    tv.tv_sec = seconds;
    tv.tv_usec = usec;

    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
}

int conn()
{
    const char *google_dns_server = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    //Socket could not be created
    if (sock < 0)
    {
        perror("Socket error");
    }

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(google_dns_server);
    serv.sin_port = htons(dns_port);

    int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));
    printf("err is %d\n", err);
    close(sock);
    return err==0 ? 1:0;
}

char *matchvalue(char *str, char *match)
{
    // printf("%s\n", str);
    char *pos = strstr(str, match);

    char *start_pos = pos+strlen(match)+2;

    char *end_pos;
    int len = 0;
    for(end_pos = start_pos+1; *end_pos!='"'; end_pos++)
    {
        // printf("%c", *end_pos);
        len++;
    }
    char *ret = (char *)malloc(sizeof(char)*(len+1));
    memset(ret, '\0', len+1);
    strncpy(ret, start_pos+1, len);
    return ret;
}

char *request(int port, char *hostname, char *uri)
{
    char *req_str = (char *)malloc(sizeof(char)*512);
    sprintf(req_str, "GET %s HTTP/1.1\r\n"
                    "Host: %s:%d\r\n"
                    "Connection: close\r\n"
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36 Edg/96.0.1054.53\r\n"
                    "\r\n", uri, hostname, port);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    struct hostent *host;
    host = gethostbyname(hostname);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if(sockfd<0){
        printf("sock open error!");
        exit(0);
    }

    int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    socket_set_timeout(sockfd, 1, 0);

    //send
    send(sockfd, req_str, strlen(req_str), 0);
    free(req_str);
    //recv
    ssize_t length = 0;
    char buf[10240];
    memset(buf, 0, sizeof(buf));

    char *response = calloc(1024, sizeof(char));
    do
    {
        length = recv(sockfd, buf, sizeof(buf), 0);

        if (length>0)
        {
            //leak mem
            char *pp = realloc(response, strlen(response) + length + 1);
            if (!pp)
            {
                break;
            }
            response = pp;
            memcpy(response + strlen(response), buf, length);
            memset(buf, 0x0, sizeof(buf));
        }
    } while (length > 0);
    close(sockfd);

    return response;
}

char *getip()
{
    char *response = request(80, "192.168.200.2", "/drcom/chkstatus?callback=dr1002&v=924");
    // printf("%s\n%d\n", response, strlen(response));
    char *body_pos = strstr(response, "\r\n\r\n");
    char *localip = matchvalue(body_pos, "ss5");

    free(response);
    return localip;
}

int login(char *username, char *password, char *operator, int device)
{
    char *ip = getip();

    char url[512] = {'\0'};

    sprintf(url,
                "/eportal/?c=Portal&a=login&login_method=1&user_account=,%d,%s@%s&user_password=%s&wlan_user_ip=%s&wlan_user_ipv6=&wlan_user_mac=000000000000",
                device,
                username,
                operator,
                password,
                ip
                );

    // printf("url is %s\n", url);

    char *response = request(801, "192.168.200.2", url);

    char *body_pos = strstr(response, "\r\n\r\n")+4;

    // printf("RESPONSE BODY: \n%s\n", body_pos);

    char *msg = matchvalue(body_pos, "msg");

    // printf("RESPONSE: %s\n", body_pos);
    int ret;
    if(strlen(msg)==0){
        printf("已经登录！\n");
        ret = 1;
    }else if(!strcmp(msg, "\\u8ba4\\u8bc1\\u6210\\u529f")){
        printf("登录成功！\n");
        ret = 1;
    }else if(!strcmp(msg, "bGRhcCBhdXRoIGVycm9y")){
        printf("密码错误！\n");
        ret = 2;
    }else if(!strcmp(msg, "aW51c2UsIGxvZ2luIGFnYWluL")){
        printf("正在重试...\n");
        ret = login(username, password, operator, device);
    } else {
        ret = 4;
    }

    free(response);
    return ret;
}

void help()
{
    printf("usage: ./program user pwd operator device\n\n");
    printf("operator: cmcc or telecom\n");
    printf("device: pc or phone\n");
}

int main(int argc, char **argv)
{
    if(argc<5){
        help();
        return -1;
    }
    int ret, con;
    char username[20], *password[20], operator[10];
    int device;
    char hostname[] = "baidu.com";
    strcpy(username, argv[1]);
    strcpy(password, argv[2]);
    strcpy(operator, argv[3]);
    if(strcmp(argv[4], "phone")){
        device = 0;
    }else if(strcmp(argv[4], "pc")){
        device = 1;
    }else{
        printf("device arg error!\n");
        exit(1);
    }
    // printf("username: %s\n", username);
    // printf("pwd: %s\n", password);
    // printf("operator: %s\n", operator);
    // printf("device: %d\n", device);
    while(1){
        con = ping_host_ip(hostname);
        printf("conn: %d\n", con);
        if(con<0){
            ret = login(username, password, operator, device);
            if(ret == 4 || ret==2) exit(0);
        }
        sleep(1);
    }

    return 0;
}