#define APP_NAME        "sniffex"
#define APP_DESC        "Sniffer example using libpcap"
#define APP_COPYRIGHT    "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER    "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <ctime>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

FILE *file;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

    fprintf(file,"%s - %s\n", APP_NAME, APP_DESC);
    fprintf(file,"%s\n", APP_COPYRIGHT);
    fprintf(file,"%s\n", APP_DISCLAIMER);
    fprintf(file,"\n");

    return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

    fprintf(file,"Usage: %s [interface]\n", APP_NAME);
    fprintf(file,"\n");
    fprintf(file,"Options:\n");
    fprintf(file,"    interface    Listen on <interface> for packets.\n");
    fprintf(file,"\n");

    return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    fprintf(file,"%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        fprintf(file,"%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            fprintf(file," ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        fprintf(file," ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            fprintf(file,"   ");
        }
    }
    fprintf(file,"   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            fprintf(file,"%c", *ch);
        else
            fprintf(file,".");
        ch++;
    }

    fprintf(file,"\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                    /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    time_t now = time(0);
    tm *ltm = localtime(&now);
    fprintf(file,"\nDate and time of capture: %d.%d.%d %d:%d", ltm->tm_mday, 1+ltm->tm_mon, 1900 + ltm->tm_year, ltm->tm_hour, ltm->tm_min);

    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    fprintf(file,"\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        fprintf(file,"   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    //printf("       From: %s\n", inet_ntoa(ip->ip_src));
    //printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    struct sockaddr_in ip4addr;
    memset(&ip4addr, 0, sizeof(struct sockaddr_in));
    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons(0);
    inet_pton(AF_INET, inet_ntoa(ip->ip_src), &ip4addr.sin_addr);

    char host[NI_MAXHOST], service[NI_MAXSERV];
    int s = getnameinfo((struct sockaddr *) &ip4addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);

    struct sockaddr_in ip4addr2nd;
    memset(&ip4addr2nd, 0, sizeof(struct sockaddr_in));
    ip4addr2nd.sin_family = AF_INET;
    ip4addr2nd.sin_port = htons(0);
    inet_pton(AF_INET, inet_ntoa(ip->ip_dst), &ip4addr2nd.sin_addr);
    char client[NI_MAXHOST], service2[NI_MAXSERV];
    int chio = getnameinfo((struct sockaddr *) &ip4addr2nd, sizeof(struct sockaddr_in), client, NI_MAXHOST, service2, NI_MAXSERV, NI_NUMERICSERV);

    if (s == 0) {
        fprintf(file,"From: %s\n", host);
        //return 0;
    }
    else {
        fprintf(file,"Failed getnameinfo\n");
        //return 2;
    }
    if (chio == 0){
        fprintf(file,"To: %s\n", client);
    }
    else {
        fprintf(file,"Failed getnameinfo\n");
    }

    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            fprintf(file,"   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            fprintf(file,"   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            fprintf(file,"   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            fprintf(file,"   Protocol: IP\n");
            return;
        default:
            fprintf(file,"   Protocol: unknown\n");
            return;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        fprintf(file,"   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    fprintf(file,"   Src port: %d\n", ntohs(tcp->th_sport));
    fprintf(file,"   Dst port: %d\n", ntohs(tcp->th_dport));

    /* define/compute tcp payload (segment) offset */
    //payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    payload = (const char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        fprintf(file,"   Payload (%d bytes):\n", size_payload);
        print_payload((const u_char*)payload, size_payload);
    }

    return;
}

int main(int argc, char **argv)
{
    file = fopen("result.txt", "w");
    //std::vector<char[60000]> resulting_string;

    /////////////////////////////////////////////////////////
    if (argc > 1 && *(argv[1]) == '-') {
    //usage();
    exit(1);
    }
    //create a socket
    int s0 = socket(AF_INET, SOCK_STREAM, 0);
    if (s0 < 0){
    perror ("Cannot create a socket"); exit(1);
    }
    // Fill in the address of server
    struct sockaddr_in peeraddr;
    memset(&peeraddr, 0, sizeof(peeraddr));
    const char* peerHost = "localhost";
    if (argc > 1)
    peerHost = argv[1];
    // Resolve the server address (convert from symbolic name to IP number)
    struct hostent *host = gethostbyname(peerHost);
    if (host == NULL) {
    perror("Cannot define host address"); exit(1);
    }
    peeraddr.sin_family = AF_INET;
    short peerPort = 1234;
    if (argc >= 3)
    peerPort = (short) atoi(argv[2]);
    peeraddr.sin_port = htons(peerPort);
    // Print a resolved address of server (the first IP of the host)
    fprintf(file,
    "peer addr = %d.%d.%d.%d, port %d\n",
    host->h_addr_list[0][0] & 0xff,
    host->h_addr_list[0][1] & 0xff,
    host->h_addr_list[0][2] & 0xff,
    host->h_addr_list[0][3] & 0xff,
    (int) peerPort
    );

    // Write resolved IP address of a server to the address structure
    memmove(&(peeraddr.sin_addr.s_addr), host->h_addr_list[0], 4);

    // Connect to a remote server
    int res = connect(s0, (struct sockaddr*) &peeraddr, sizeof(peeraddr));
    if (res < 0) {
    perror("Cannot connect"); exit(1);
    }
    printf("Connected. Reading a server message.\n");

    char buffer[1024];

    for (;;) {
    res = read(s0, buffer, 1024);
    if (res < 0) {
    perror("Read error");
    exit(1);
    }
    printf("Received:\n%s", buffer);

    //write(s0, "Thanks! Bye-bye...\r\n", 20);

    //close(s0);

    if (buffer == "close") {
    close(s0);
    exit(0);
    }
    if (buffer == "send") {
    //write(s0, (char *) (resulting_string.size()) + '|', sizeof(resulting_string.size()));
    write(s0, file, sizeof(file));// если выйдем за предлы 60000 байт запустить цикл с write ведь каретка останется на конце прошлого write
    //write(s0, resulting_string, sizeof(resulting_string));
    } else {
    if (buffer != "write") fprintf(stderr, "error: wrong command\n\n");
    else {
    //////////////////////////////////////////////////////////////////////////
    char *dev = NULL; /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
    pcap_t *handle; /* packet capture handle */

    char filter_exp[] = "ip"; /* filter expression [3] */
    struct bpf_program fp; /* compiled filter program (expression) */
    bpf_u_int32 mask; /* subnet mask */
    bpf_u_int32 net; /* ip */
    int num_packets = 250; /* number of packets to capture */

    print_app_banner();

    /* check for capture device name on command-line */
    if (argc == 2) {
    dev = argv[1];
    } else if (argc > 2) {
    fprintf(stderr, "error: unrecognized command-line options\n\n");
    print_app_usage();
    exit(EXIT_FAILURE);
    } else {
    /* find a capture device if not specified on command-line */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n",
    errbuf);
    exit(EXIT_FAILURE);
    }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
    dev, errbuf);
    net = 0;
    mask = 0;
    }

    /* print capture info */
    fprintf(file,"Device: %s\n", dev);
    //fprintf(file,"Number of packets: %d\n", num_packets);
    fprintf(file,"Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
    filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
    filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */

    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");
    fprintf(file,"\nCapture complete.\n" );
    //return 0;
    }
    }
    }
    }
