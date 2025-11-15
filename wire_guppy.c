#include "fire.h"

//so this firewall is going to be a server... so it should behave like a server
int main(){

    // THIS IS SERVER CODE, NOT NECESSARY FOR WIRESHARK PORTION OF PROJECT
    struct sockaddr_in addr;
    //no sneaky data!
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; // IPv4
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, HOST, &addr.sin_addr);
    //connection socket; we will only use tcp for now, but maybe support udp in the future
    int connection_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (connection_socket == -1){
        handle_error(CONN_SOCK);
    } else{printf("connection socket created\n");}

    if (bind(connection_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1){
        handle_error(BIND);
    } else{printf("connection socket for address: %s bound to port: %d\n", HOST, PORT);}

    if (listen(connection_socket, 10) == -1){
        handle_error(LISTEN);
    } else{printf("connection socket listening for connections...");}

    /* ~~~BERKELEY PACKET FILTER /DEV/BPF0 raw packet capture!!!~~~*/
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "en0", sizeof(ifr.ifr_name));

    int packet_filter_fd = open("/dev/bpf0", O_RDWR);
    if (packet_filter_fd == -1){
        handle_error(BPF);
    }
    if (ioctl(packet_filter_fd, BIOCSETIF, &ifr) < 0){
        handle_error(BIOCSETIF);
    }
    u_int one = 1;
    if (ioctl(packet_filter_fd, BIOCIMMEDIATE, &one) < 0){
        handle_error(BIOCIMMEDIATE);
    }

    //promiscuous mode
    if (ioctl(packet_filter_fd, BIOCPROMISC, NULL) < 0){
        handle_error(BIOCPROMISC);
    }

    u_int buf_len;
    if (ioctl(packet_filter_fd, BIOCGBLEN, &buf_len) < 0){
        printf("error retrieving buffer size\n");
    }

    printf("buffer size: %d\n", buf_len);

    char *buf = (char *)malloc(buf_len);

    printf("listeing on en0 using /dev/bpf0\n");

    struct pollfd poll_fd = {
        .fd = packet_filter_fd,
        .events = POLLIN,
    };

    //a servers gotta serve
    printf("# bytes\t|\tNwrkProto\t|\tTrnsprtProto\t|\t src → dest\t|\n\n");
    for(;;){
        /*
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        int client_socket = accept(connection_socket, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if (client_socket == -1){
            handle_error(CLIENT_SOCK);
        } else{printf("great\n");}
        */


        if (poll(&poll_fd, 1, -1) < 0){
            perror("poll");
            printf("poll\n");
            break;
        }
        if (poll_fd.revents & POLLIN){
            int n = read(packet_filter_fd, buf, buf_len);
            if (n < 0){
                perror("read");
                break;
            }

            printf("%zd bytes\t", n);

            u_char *ptr = buf;
            while(ptr < buf + n){
                struct bpf_hdr *hdr = (struct bpf_hdr *)ptr;
                //payload is offset by header length
                const u_char *payload = ptr + hdr->bh_hdrlen;

                //checking ethernet type
                struct ether_header *eth = (struct ether_header *) payload;
                

                /* IPv4 */
                if (ntohs(eth->ether_type) == ETHERTYPE_IP){
                    printf("IPv4:\t");
                    //our packet offset by the size of the ethernet frame header
                    struct ip *ip_hdr = (struct ip *)(payload + sizeof(struct ether_header));
                    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip_hdr->ip_src, src, sizeof(src));
                    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst, sizeof(dst));
                    //TCP
                    if (ip_hdr->ip_p == IPPROTO_TCP){
                        //tcp header
                        //try looking only for dns!
                        struct tcphdr *tcp_hdr = (struct tcphdr *)(payload + sizeof(struct ether_header) + ip_hdr->ip_hl*4);
                        //if (ntohs(tcp_hdr->th_dport) != 53 && ntohs(tcp_hdr->th_sport) != 53){continue;}
                        printf("TCP\t%s:%d → %s:%d\n",src, ntohs(tcp_hdr->th_sport), dst, ntohs(tcp_hdr->th_dport));
                        unsigned char *tcp_payload = (unsigned char *)tcp_hdr + (4*tcp_hdr->th_off);
                        int tcp_payload_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - (tcp_hdr->th_off * 4);
                        printf("payload:\n");
                        /*
                        for (int i = 0; i < tcp_payload_len; i++){
                            unsigned char c = tcp_payload[i];
                            if (c >= 32 && c <= 126){
                                putchar(c);
                            }else {
                                putchar('.');
                            }
                        }
                        */
                        print_strings(tcp_payload, tcp_payload_len, 5);
                        printf("\n\n");
                    }
                    //UDP
                    else if (ip_hdr->ip_p == IPPROTO_UDP) {
                        struct udphdr *udp_hdr = (struct udphdr *)(payload + sizeof(struct ether_header) + ip_hdr->ip_hl*4);
                        //if (ntohs(udp_hdr->uh_dport) != 53 && ntohs(udp_hdr->uh_sport) != 53){continue;}
                        printf("UDP\t%s:%d → %s:%d\n", src, ntohs(udp_hdr->uh_sport), dst, ntohs(udp_hdr->uh_dport));
                        unsigned char *udp_payload = (unsigned char *)udp_hdr + sizeof(struct udphdr);
                        int udp_payload_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - sizeof(struct udphdr);
                        printf("payload:\n");
                        /*for (int i = 0; i < udp_payload_len; i++){
                            unsigned char c = udp_payload[i];
                            if (c >= 32 && c <= 126){
                                putchar(c);
                            }else {
                                putchar('.');
                            }
                        }*/
                        print_strings(udp_payload, udp_payload_len, 5);
                        printf("\n\n");
                    }
                }
                /* ADDRESS RESOLUTION */
                else if (ntohs(eth->ether_type) == ETHERTYPE_ARP){
                    printf("ARP(address resolution protocol) -> maps an IPv4 address to a MAC address! sending packets across Local Area Networks\t\n\n");
                }
                else if (ntohs(eth->ether_type) == ETHERTYPE_REVARP){
                    printf("reverse ARP: OBSOLETE! if this line runs, i have some questions to ask!\t\n\n");
                }
                /* IPv6 */
                else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6){
                    printf("IPv6:\t");
                    struct ip6_hdr *ip_hdr = (struct ip6_hdr *)(payload + sizeof(struct ether_header));
                    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip_hdr->ip6_src, src, sizeof(src));
                    inet_ntop(AF_INET, &ip_hdr->ip6_dst, dst, sizeof(dst));
                    //TCP
                    if (ip_hdr->ip6_nxt == IPPROTO_TCP){
                        //tcp header
                        struct tcphdr *tcp_hdr = (struct tcphdr *)(payload + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                        //if (ntohs(tcp_hdr->th_dport) != 53 && ntohs(tcp_hdr->th_sport) != 53){continue;}
                        printf("TCP\t%s:%d → %s:%d\n",src, ntohs(tcp_hdr->th_sport), dst, ntohs(tcp_hdr->th_dport));
                        unsigned char *tcp_payload = (unsigned char *)tcp_hdr + (4*tcp_hdr->th_off);
                        int tcp_payload_len = ntohs(ip_hdr->ip6_plen) - sizeof(struct tcphdr);
                        printf("payload:\n");
                        /*
                        for (int i = 0; i < tcp_payload_len; i++){
                            unsigned char c = tcp_payload[i];
                            if (c >= 32 && c <= 126){
                                putchar(c);
                            }else {
                                putchar('.');
                            }
                        }
                        */
                        print_strings(tcp_payload, tcp_payload_len, 5);
                        printf("\n\n");
                    }
                    //UDP
                    else if (ip_hdr->ip6_nxt == IPPROTO_UDP) {
                        struct udphdr *udp_hdr = (struct udphdr *)(payload + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                        //if (ntohs(udp_hdr->uh_dport) != 53 && ntohs(udp_hdr->uh_sport) != 53){continue;}
                        printf("UDP\t%s:%d → %s:%d\n", src, ntohs(udp_hdr->uh_sport), dst, ntohs(udp_hdr->uh_dport));
                        unsigned char *udp_payload = (unsigned char *)udp_hdr + sizeof(struct udphdr);
                        int udp_payload_len = ntohs(ip_hdr->ip6_plen) - sizeof(struct udphdr);
                        printf("payload:\n");
                        /*
                        THIS IS FOR PRINTING ASCII CHARACTERS WITH UNPRINTABLE CHARACTERS
                        for (int i = 0; i < udp_payload_len; i++){
                            unsigned char c = udp_payload[i];
                            if (c >= 32 && c <= 126){
                                putchar(c);
                            }else {
                                putchar('.');
                            }
                        }
                        */
                        print_strings(udp_payload, udp_payload_len, 5);
                        printf("\n\n");
                    }
                }
                else{
                    printf("we didn't account for this eth type yet! ether_type: %d,\t", ntohs(eth->ether_type));
                }

                ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            }
        }
    }

    free(buf);
    close(packet_filter_fd);
    return 0;

}

void handle_error(ErrorType e){
    if (e == CONN_SOCK){
        printf("error creating connection socket, server never got off of the ground! :(\n");
    } else if (e == BIND){
        printf("error binding connection socket to address: %s port: %d\n", HOST, PORT);
    } else if (e == LISTEN){
        printf("error listening for connections\n");
    } else if (e == BPF){
        printf("error opening /dev/bpf0\n");
    }else if (e == BIOCSETIF){
        printf("error binding to en0 interface\n");
    }else if (e == BIOCIMMEDIATE){
        printf("error setting BIOIMMEDIATE flag for immediate reads of /dev/bpf0\n");
    }else if (e == BIOCPROMISC){
        printf("error setting BIOPROMISC mode for /dev/bpf0\n");
    }
    else{printf("something went wrong, you figure it out...\n");}

    exit(1);
}
