#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libnet-headers.h"

void usage() 
{
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) 
{
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void parse_ethernet_hdr(const u_char *eth_packet, struct libnet_ethernet_hdr *hdr)
{
    struct libnet_ethernet_hdr *packet = (struct libnet_ethernet_hdr *)eth_packet;

    memcpy(hdr->ether_dhost, packet->ether_dhost, ETHER_ADDR_LEN);
    memcpy(hdr->ether_shost, packet->ether_shost, ETHER_ADDR_LEN);
    hdr->ether_type = ntohs(packet->ether_type);
}

void parse_ipv4_hdr(const u_char *ip_packet, struct libnet_ipv4_hdr *hdr)
{
    struct libnet_ipv4_hdr *packet = (struct libnet_ipv4_hdr *)ip_packet;

    hdr->ip_hl  = packet->ip_hl;
    hdr->ip_v   = packet->ip_v;
    hdr->ip_tos = packet->ip_tos;
    hdr->ip_len = ntohs(packet->ip_len);
    hdr->ip_id  = ntohs(packet->ip_id);
    hdr->ip_off = ntohs(packet->ip_off);
    hdr->ip_ttl = packet->ip_ttl;
    hdr->ip_p   = packet->ip_p;
    hdr->ip_sum = ntohs(packet->ip_sum);
    hdr->ip_src = packet->ip_src;
    hdr->ip_dst = packet->ip_dst;
}

void parse_tcp_hdr(const u_char *tcp_packet, struct libnet_tcp_hdr *hdr)
{
    struct libnet_tcp_hdr *packet = (struct libnet_tcp_hdr *)tcp_packet;

    hdr->th_sport   = ntohs(packet->th_sport);
    hdr->th_dport   = ntohs(packet->th_dport);
    hdr->th_seq     = ntohl(packet->th_seq);
    hdr->th_ack     = ntohl(packet->th_ack);
    hdr->th_x2      = packet->th_x2;
    hdr->th_off     = packet->th_off;
    hdr->th_flags   = packet->th_flags;
    hdr->th_win     = ntohs(packet->th_win);
    hdr->th_sum     = ntohs(packet->th_sum);
    hdr->th_urp     = ntohs(packet->th_urp);
}

void print_packet_info(struct libnet_ethernet_hdr* eth_hdr, struct libnet_ipv4_hdr* ipv4_hdr, 
                        struct libnet_tcp_hdr* tcp_hdr, const u_char *data, uint32_t data_len)
{
    static int cnt = 1;
    int i = 0;
    char *ip_src;
    char *ip_dst;

    printf("%dTH PACKET\n", cnt);

    printf("============= <ETHERNET HEADER> =============\n"
           "src mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
           "dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n\n", 
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5],
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
    
    ip_src = strdup(inet_ntoa(ipv4_hdr->ip_src));
    ip_dst = strdup(inet_ntoa(ipv4_hdr->ip_dst));
    printf("=============   <IPV4 HEADER>   =============\n"
           "src ip: %s\n"
           "dst ip: %s\n\n",
           ip_src, ip_dst);
    free(ip_src);
    free(ip_dst);

    printf("=============   <TCP  HEADER>   =============\n"
           "src port: %hu\n"
           "dst port: %hu\n\n",
           tcp_hdr->th_sport, tcp_hdr->th_dport);

    printf("=============       <DATA>      =============\n");
    while (i < 10 && i < data_len){
        printf("%02x ", data[i]);
        i++;
    }
    printf("\n\n\n");

    cnt++;
}

void parse_packet(const u_char *packet, uint32_t packet_len)
{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_ipv4_hdr ipv4_hdr;
    struct libnet_tcp_hdr tcp_hdr;
    uint32_t data_len;

    if (packet_len < ETHER_HDR_LEN)
        return;

    parse_ethernet_hdr(packet, &eth_hdr);
    if (eth_hdr.ether_type != ETHER_TYPE_IPV4 || packet_len < ETHER_HDR_LEN + IPV4_HDR_LEN)
        return;
    packet = packet + ETHER_HDR_LEN;
    
    parse_ipv4_hdr(packet, &ipv4_hdr);
    if (ipv4_hdr.ip_p != IPV4_PROTOCOL_TCP || packet_len < ETHER_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN)
        return;
    packet = packet + IPV4_HDR_LEN;
    
    parse_tcp_hdr(packet, &tcp_hdr);
    packet = packet + tcp_hdr.th_off * 4;

    data_len = ipv4_hdr.ip_len - IPV4_HDR_LEN - tcp_hdr.th_off * 4;
    
    print_packet_info(&eth_hdr, &ipv4_hdr, &tcp_hdr, packet, data_len);
}

int main(int argc, char *argv[]) 
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        parse_packet(packet, header->caplen);
    }

    pcap_close(pcap);
}

