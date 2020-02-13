#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>

struct session {
    int src;
    int dst;
    int syn_f;
    int ack_f;
    int fin_f;
    int syn_t;
    int ack_t;
    int fin_t;
};

struct chain {
    struct session* data;
    struct chain* next;
};

struct chain* start = NULL;
struct chain* next = NULL;
int sessions_count = 0;
int success_connect = 0;
int success_close = 0;
// int reset = 0;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;

    ethernetHeader = (struct ether_header*)packet;

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            bool find_chain = false;
    
            if (!start) {

                struct session* s = (struct session*)malloc(sizeof(struct session));

                s->src = ipHeader->ip_src.s_addr;
                s->dst = ipHeader->ip_dst.s_addr;
                s->syn_f = tcpHeader->syn;
                s->ack_f = tcpHeader->ack;
                s->fin_f = tcpHeader->fin;
                s->syn_t = 0;
                s->ack_t = 0;
                s->fin_t = 0;

                start = (struct chain*)malloc(sizeof(struct chain));

                start->data = s;
                start->next = NULL;

                next = start;

                find_chain = true;
                sessions_count++;
            }

            struct chain* current = start;

            int i = 0;

            do {

                if (current->data->src == ipHeader->ip_src.s_addr &&
                    current->data->dst == ipHeader->ip_dst.s_addr) {

                    find_chain = true;

                    if (tcpHeader->syn) current->data->syn_f++;
                    if (tcpHeader->ack) {
                        current->data->ack_f++;

                        if (current->data->syn_f && current->data->ack_t && current->data->syn_t) {
                            success_connect++;

                            current->data->syn_f = 0;
                            current->data->ack_f = 0;
                            current->data->syn_t = 0;
                            current->data->ack_t = 0;
                        }
                    }
                    // if (tcpHeader->rst) {
                    //     reset++;

                    //     current->data->syn_f = 0;
                    //     current->data->ack_f = 0;
                    //     current->data->fin_f = 0;

                    //     current->data->syn_t = 0;
                    //     current->data->ack_t = 0;
                    //     current->data->fin_t = 0;
                    // }
                    if (tcpHeader->ack && tcpHeader->fin) {
                        current->data->fin_f++;

                        if (current->data->ack_t && current->data->fin_t) {
                            success_close++;

                            current->data->syn_f = 0;
                            current->data->ack_f = 0;
                            current->data->fin_f = 0;

                            current->data->syn_t = 0;
                            current->data->ack_t = 0;
                            current->data->fin_t = 0;
                        }
                    }

                    break;
                }

                if (current->data->src == ipHeader->ip_dst.s_addr && 
                    current->data->dst == ipHeader->ip_src.s_addr) {

                    // printf("src %d, dst %d, src %d, dst %d\n", 
                    //     current->data->src, current->data->dst, ipHeader->ip_src.s_addr, ipHeader->ip_dst.s_addr);

                    find_chain = true;

                    if (tcpHeader->syn) current->data->syn_t++;
                    if (tcpHeader->ack) {
                        current->data->ack_t++;

                        if (current->data->syn_t && current->data->ack_f && current->data->syn_f) {
                            success_connect++;

                            current->data->syn_f = 0;
                            current->data->ack_f = 0;
                            current->data->syn_t = 0;
                            current->data->ack_t = 0;
                        }
                    }
                    // if (tcpHeader->rst) {
                    //     reset++;

                    //     current->data->syn_f = 0;
                    //     current->data->ack_f = 0;
                    //     current->data->fin_f = 0;

                    //     current->data->syn_t = 0;
                    //     current->data->ack_t = 0;
                    //     current->data->fin_t = 0;
                    // }
                    if (tcpHeader->ack && tcpHeader->fin) {
                        current->data->fin_t++;
                        
                        if (current->data->ack_f && current->data->fin_f) {
                            success_close++;

                            current->data->syn_f = 0;
                            current->data->ack_f = 0;
                            current->data->fin_f = 0;

                            current->data->syn_t = 0;
                            current->data->ack_t = 0;
                            current->data->fin_t = 0;
                        }
                    }

                    break;
                }

                i++;
            } while ((current = current->next));
    
            if (!find_chain) {

                struct session* s = (struct session*)malloc(sizeof(struct session));

                s->src = ipHeader->ip_src.s_addr;
                s->dst = ipHeader->ip_dst.s_addr;
                s->syn_f = tcpHeader->syn;
                s->ack_f = tcpHeader->ack;
                s->fin_f = tcpHeader->fin;
                s->syn_t = 0;
                s->ack_t = 0;
                s->fin_t = 0;

                struct chain* ch = (struct chain*)malloc(sizeof(struct chain));

                ch->data = s;
                ch->next = NULL;

                next->next = ch;

                next = ch;

                sessions_count++;
            }
        }
    }
}

int main(int argc , char* argv[]) {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    char abspath[PATH_MAX];

    if (argc < 2) {
        printf("not found filepath\n");
        return 1;
    }

    realpath(argv[1], abspath);

    descr = pcap_open_offline(abspath, errbuf);
    
    if (descr == NULL) {
        printf("pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }
    
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        printf("pcap_loop() failed: %s\n", pcap_geterr(descr));
        return 1;
    }
    
    printf("sessions_count: %d\n",    sessions_count);
    printf("success_connect: %d\n",   success_connect);
    printf("succeeded_close: %d\n",   success_close);
    printf("unclosed_sessions: %d\n", sessions_count - success_close);
    
    return 0;
}