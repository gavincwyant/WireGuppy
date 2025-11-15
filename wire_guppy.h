#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>


#define PORT 1234
#define HOST "127.0.0.1"
#define BUF_LEN 1024000

typedef enum {CONN_SOCK, CLIENT_SOCK, BIND, LISTEN, BPF}ErrorType;

void handle_error(ErrorType);

void print_strings(const unsigned char *data, size_t len, int min_len);
