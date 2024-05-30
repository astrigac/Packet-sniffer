/*
 * IPK Project 2 - ZETA: Network sniffer
 * Author: Aurel Strigac <xstrig00@vutbr.cz>
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <time.h>

#define MAX_INTERFACE_LENGTH 40
#define MAX_FILTER_LENGTH 200
#define SIZE_ETHERNET 14

char error_buffer[PCAP_ERRBUF_SIZE];

/** 
 * From:
 * Programing with pcap
 * https://www.tcpdump.org/pcap.html
 */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/**
 * Enum for the error codes
 * 
 * From:
 * Converting from String to Enum in C
 * https://stackoverflow.com/questions/16844728/converting-from-string-to-enum-in-c
 */
typedef enum
{
    DIGIT,
    ARGS,
    IFACE,
    INVALID_IFACE,
    INVALID_PORT,
    MULTI,
    NO_IFACE,
    LAST_ENTRY //This is here just so I don't have to change printError() everytime new error is added
} ErrorCode;

/**
 * Error descriptions
 * 
 * From:
 * Converting from String to Enum in C
 * https://stackoverflow.com/questions/16844728/converting-from-string-to-enum-in-c
 */
const char* errorDesc[] =
{
    "Digit argument in wrong format\n",
    "Wrong function arguments\n",
    "Error in pcap_findall_devs(): ",
    "Interface does not exist\n",
    "Port does not exist\n",
    "Each argument can be used only once\n",
    "Interface has not been set\n",
    "Dummy"
};

// Function for printing help message
void printHelp() 
{
    printf("Usage: ./ipk-sniffer -h [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--ndp] [--igmp] [--mld] {-n num}\n");
    printf("\t-h                          show help message\n");
    printf("\t-i | --interface            if no argument given, lists available interfaces, else specify interface\n");
    printf("\t-t | --tcp                  will display TCP segments\n");
    printf("\t-u | --udp                  will display UDP datagrams\n");
    printf("\t-p                          extends previous two parameters to filter TCP/UDP based on port number\n");
    printf("\t--icmp4                     will display only ICMPv4 packets\n");
    printf("\t--icmp6                     will display only ICMPv6 echo request/response\n");
    printf("\t--arp                       will display only ARP frames\n");
    printf("\t--ndp                       will display only ICMPv6 NDP packets\n");
    printf("\t--igmp                      will display only IGMP packets\n");
    printf("\t--mld                       will display only MLD packets\n");
    printf("\t-n                          set packet limit, must be positive (unlimited if not set)\n");
}

/**
 * Function for printing all kinds of errors based on ErrorCode
 * 
 * From:
 * Converting from String to Enum in C
 * https://stackoverflow.com/questions/16844728/converting-from-string-to-enum-in-c
 */
void printError(ErrorCode c)
{
    //Validate..
    if( c < LAST_ENTRY)
    {   
        fprintf(stderr, "%s", errorDesc[c]);
        fprintf(stderr, "For more info, use ./ipk-sniffer -h");
    }
}

// Function for printing all active interfaces on current machine
void printActiveInterfaces() {
    pcap_if_t *interfaces;
    char error_buffer[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&interfaces, error_buffer) == 0) {
        printf("List of active interfaces:\n");
        for (pcap_if_t *interface = interfaces; interface != NULL; interface = interface->next) {
            if (interface->flags & PCAP_IF_UP && interface->flags & PCAP_IF_RUNNING) {
                printf("%s\n", interface->name);
            }
        }
        pcap_freealldevs(interfaces);
    }
    else {
        fprintf(stderr, "Error finding interfaces: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }
}

/**
 * Function for checking wether interface exist on the current machine or not
 * 
 * From:
 * Find the IPv4 network number and netmask for a device 
 * https://www.tcpdump.org/manpages/pcap_lookupnet.3pcap.html
*/
void checkInterface(char name[]) {
    bpf_u_int32 net, mask;

    /* Lookup the network number and mask for the interface */
    if (pcap_lookupnet(name, &net, &mask, error_buffer) == -1)
    {
        printError(INVALID_IFACE);
        exit(EXIT_FAILURE);
    }
    return;
}

/** 
 * Function for checking port parameter
 * 
 * From:
 * What is the largest TCP/IP network port number allowable for IPv4?
 * https://stackoverflow.com/questions/113224/what-is-the-largest-tcp-ip-network-port-number-allowable-for-ipv4
*/
void checkPort(int port) {
    if(port < 1 || port > 65535) {
        printError(INVALID_PORT);
        exit(EXIT_FAILURE);
    }
}

void checkDigitOptarg(char *optarg) {
    for(size_t i = 0; i < strlen(optarg); i++) {
        if(!isdigit(optarg[i])){
            printError(DIGIT);
            exit(EXIT_FAILURE);
        }
    }
}

void repetetiveArgumentPrevent(int *arg) {
    if(*arg){
        printError(MULTI);
        exit(EXIT_FAILURE);
    }
}

// Function for parsing arguments
void parseArguments(int argc, char *argv[], char interface[], int *tcp, int *udp, int *port, int *arp, int *icmp4, int *icmp6, int *ndp, int *igmp, int *mld, int *num) {
    int option;

    // From:
    // Parsing program options using getopt
    // https://www.gnu.org/software/libc/manual/html_node/Getopt.html
    struct option long_options[] = {
        {"interface", optional_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 'a'},
        {"icmp4", no_argument, 0, 'b'},
        {"icmp6", no_argument, 0, 'c'},
        {"ndp", no_argument, 0, 'd'},
        {"igmp", no_argument, 0, 'e'},
        {"mld", no_argument, 0, 'f'},
        {0, 0, 0, 0}
    };

    while ((option = getopt_long(argc, argv, "hi::tup:n:abcdef", long_options, NULL)) != -1) {
        switch (option) {
            case 'h':
                printHelp();
                exit(0);
                break;
            case 'i':
                if(argc == 2){
                    printActiveInterfaces();
                    exit(0);
                }
                if(argv[optind][0] == '-' || argv[optind] == NULL){
                    printError(ARGS);
                    exit(EXIT_FAILURE);
                }
                strcpy(interface, argv[optind]);
                checkInterface(interface);
                break;
            case 'p':
                checkDigitOptarg(optarg);
                *port = atoi(optarg);
                checkPort(*port);
                break;
            case 'n':
                checkDigitOptarg(optarg);
                *num = atoi(optarg);
                break;
            case 't':
                repetetiveArgumentPrevent(tcp);
                *tcp = 1;
                break;
            case 'u':
                repetetiveArgumentPrevent(udp);
                *udp = 1;
                break;
            case 'a':
                repetetiveArgumentPrevent(arp);
                *arp =1;
                break;
            case 'b':
                repetetiveArgumentPrevent(icmp4);
                *icmp4 = 1;
                break;
            case 'c':
                repetetiveArgumentPrevent(icmp6);
                *icmp6 = 1;
                break;
            case 'd':
                repetetiveArgumentPrevent(ndp);
                *ndp = 1;
                break;
            case 'e':
                repetetiveArgumentPrevent(igmp);
                *igmp = 1;
                break;
            case 'f':
                repetetiveArgumentPrevent(mld);
                *mld = 1;
                break;
            default:
                // Invalid option or missing argument
                printError(ARGS);
                exit(EXIT_FAILURE);
        }
    }

    // If no protocol was set, catch all protocols
    if((*tcp || *udp || *arp || *icmp4 || *icmp6 || *ndp || *igmp || *mld) != 1) {
        *tcp = *udp = *arp = *icmp4 = *icmp6 = *ndp = *igmp = *mld = 1;
    } 
}

// Helping function used for putting "or" between individual filters
void printOrIfNeeded(bool *not_first, char filter_exp[], int *offset) {
    if (*not_first) {
        *offset += sprintf(filter_exp + *offset, " or");
    }
    *not_first = true;
}

/**
 * Function used for constructing various types of filters
 * 
 * From:
 * PCAP-FILTER
 * https://www.wireshark.org/docs/man-pages/pcap-filter.html
 */
void constructFilter(char filter_exp[], int tcp, int udp, int port, int arp, int icmp4, int icmp6, int ndp, int igmp, int mld) {
    int offset = 0;
    bool not_first = false;

    if (tcp) {
        if (port) {
            offset += sprintf(filter_exp + offset, " tcp port %d", port);
        } else {
            offset += sprintf(filter_exp + offset, " tcp");
        }
        not_first = true;
    }

    if (udp) {
        printOrIfNeeded(&not_first, filter_exp, &offset);
        if (port) {
            offset += sprintf(filter_exp + offset, " udp port %d", port);
        } else {
            offset += sprintf(filter_exp + offset, " udp");
        }
    }

    if (arp) {
        printOrIfNeeded(&not_first, filter_exp, &offset);
        offset += sprintf(filter_exp + offset, " arp");
    }
    if (icmp4) {
        printOrIfNeeded(&not_first, filter_exp, &offset);
        offset += sprintf(filter_exp + offset, " icmp");
    }
    if (icmp6) {
        printOrIfNeeded(&not_first, filter_exp, &offset);
        offset += sprintf(filter_exp + offset, " (icmp6 and (icmp6[0] = 128 or icmp6[0] = 129))");
    }
    if (ndp) {
        printOrIfNeeded(&not_first, filter_exp, &offset);
        offset += sprintf(filter_exp + offset, " (icmp6 and icmp6[0] = 135) or (icmp6 and icmp6[0] = 136)");
    }
    if (igmp) {
        printOrIfNeeded(&not_first, filter_exp, &offset);
        offset += sprintf(filter_exp + offset, " igmp");
    }
    if (mld) {
        printOrIfNeeded(&not_first, filter_exp, &offset);
        offset += sprintf(filter_exp + offset, " (icmp6 and (icmp6[0] = 130 or icmp6[0] = 131))");
    }
}

/**
 * Function used for convert timeval to printable string
 *
  From:
 * I'm trying to build an RFC3339 timestamp in C. How do I get the timezone offset?
 * https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
 * https://zetcode.com/articles/cdatetime/
 */
void timevalToString(struct timeval time, char result[]){
    static char buffer[128], time_buffer[64];
    time_t time_in_sec = time.tv_sec;
    struct tm *tm = localtime(&time_in_sec);

    strftime(time_buffer, sizeof time_buffer, "%FT%T", tm);

    // From:
    // Is these a way to set the output of printf to a string?
    // https://stackoverflow.com/questions/19382198/is-these-a-way-to-set-the-output-of-printf-to-a-string
    snprintf(buffer, sizeof buffer, "%s.%03ld", time_buffer, time.tv_usec/1000);
    strncpy(result, buffer, 128);
    strftime(time_buffer, 64, "%z", tm);

    char time_ending[4]=":";
    memcpy(time_ending + 1, time_buffer + 3, 2);
    time_ending[3]='\0';
    memcpy(time_buffer + 3, time_ending, 4);

    strncat(result, time_buffer, 64);
}


//Function for getting mac address in right format from string 
void getMacAddress(char *mac_buffer, const u_char *mac_bytes) {
    snprintf(mac_buffer, INET6_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
}

/**
 * Hexdump function for writing out packet informations
 *
 * From:
 * Let's Build a Hexdump Utility in C
 * http://www.dmulholl.com/lets-build/a-hexdump-utility.html
 */
void printPacketData(const u_char *data, bpf_u_int32 length){
    int line_counter = 0x0000;
    for(bpf_u_int32 i = 0; i < length; i+= 0x10) {
        printf("0x%04x: ", line_counter);
        line_counter += 0x0010;

        for (bpf_u_int32 j = 0; j < 0x10; j++) {
            if (j > 0 && j % 4 == 0)
                printf(" ");
            if (i+j < length)
                printf(" %02x", data[i+j]);
            else
                printf("   ");
        }

        printf("  ");

        for (bpf_u_int32 j = 0; j < 0x10 && i+j < length; j++) {
            if(j % 8 == 0){
                printf(" ");
            }
            if (isprint(data[i+j]))
                printf("%c", data[i+j]);
            else
                printf(".");
        }
        printf("\n");
    }
    printf("\n");
}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char mac[INET6_ADDRSTRLEN];
    char time_buf[256];

    // Extract the Ethernet header from the packet
    const struct sniff_ethernet *ethernet = (struct sniff_ethernet*)(packet);

    // Printf all information which are the same for every used protocol
    timevalToString(header->ts, time_buf);
    printf("timestamp: %s\n", time_buf);

    getMacAddress(mac, ethernet->ether_shost);
    printf("src MAC: %s\n", mac);

    getMacAddress(mac, ethernet->ether_dhost);
    printf("dst MAC: %s\n", mac);

    printf("frame length: %d bytes\n", header->len);

    uint16_t eth_type = ntohs(ethernet->ether_type);

    // IPv4 packet
    if (eth_type == ETHERTYPE_IP) {
        u_char *ip_protocol = (u_char *)(packet + SIZE_ETHERNET + 9); // src_protocol offset

        // Extract the source and destination IP addresses from the ARP packet
        struct in_addr *ip_src = (struct in_addr *)(packet + SIZE_ETHERNET + 12); // src_ip offset
        struct in_addr *ip_dst = (struct in_addr *)(packet + SIZE_ETHERNET + 16); // dst_ip offset

        u_char *ip_vhl = (u_char *)(packet + SIZE_ETHERNET);
        u_int size_ip = (*ip_vhl & 0x0f) * 4;

        printf("src IP: %s\n", inet_ntoa(*ip_src));
        printf("dst IP: %s\n", inet_ntoa(*ip_dst));

        if(*ip_protocol == IPPROTO_TCP || *ip_protocol == IPPROTO_UDP) {
            u_short *src_protocol = (u_short *)(packet + SIZE_ETHERNET + size_ip); // offset for tcp/udp
            u_short *dst_protocol = (u_short *)(packet + SIZE_ETHERNET + size_ip + sizeof(u_short));

            printf("src port: %u\n", ntohs(*src_protocol));
            printf("dst port: %u\n", ntohs(*dst_protocol));
        }
    }
    // IPv6 packet
    else if (eth_type == ETHERTYPE_IPV6) {

        char ipv6[INET6_ADDRSTRLEN] = "";
        // Extract the source and destination IP addresses from the ARP packet
        struct in6_addr *src_ip = (struct in6_addr *)(packet + SIZE_ETHERNET + 8);
        struct in6_addr *dst_ip = (struct in6_addr *)(packet + SIZE_ETHERNET + 24);

        u_char *protocol = (u_char *)(packet + SIZE_ETHERNET + 6);

        inet_ntop(AF_INET6, src_ip, ipv6, INET6_ADDRSTRLEN);
        printf("src IP: %s\n", ipv6);

        inet_ntop(AF_INET6, dst_ip, ipv6, INET6_ADDRSTRLEN);
        printf("dst IP: %s\n", ipv6);

        if(*protocol == IPPROTO_TCP || *protocol == IPPROTO_UDP) {

            u_short *src_protocol = (u_short *)(packet + SIZE_ETHERNET + 40); // offset for tcp/udp
            u_short *dst_protocol = (u_short *)(packet + SIZE_ETHERNET + 40 + sizeof(u_short));

            printf("src port: %u\n", ntohs(*src_protocol));
            printf("dst port: %u\n", ntohs(*dst_protocol));
        }
    }
    // ARP packet
    else if (eth_type == ETHERTYPE_ARP) {
        struct ether_arp *arp_header;
        arp_header = (struct ether_arp*)(packet + sizeof(struct ether_header));

        // Extract the source and destination IP addresses from the ARP packet
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(arp_header->arp_spa), src_ip_str, INET_ADDRSTRLEN);
        printf("src IP: %s\n", src_ip_str);

        inet_ntop(AF_INET, &(arp_header->arp_tpa), dst_ip_str, INET_ADDRSTRLEN);
        printf("dst IP: %s\n", dst_ip_str);
    }

    printPacketData(packet, header->len);
}

int main(int argc, char *argv[]) {

    char interface[MAX_INTERFACE_LENGTH] = "";        // Interface name
    int tcp = 0;                            // TCP flag
    int udp = 0;                            // UDP flag
    int port = 0;                           // Port number
    int arp = 0;                            // ARP flag
    int icmp4 = 0;                          // ICMPv4 flag
    int icmp6 = 0;                          // ICMPv6 flag
    int ndp = 0;                            // ICMPv6 NDP flag
    int igmp = 0;                           // IGMP flag
    int mld = 0;                            // MLD flag
    int num = 1;                            // Number of packets to display
    char pcap_filter[MAX_FILTER_LENGTH] = "";

    if(argc == 1) {
        printActiveInterfaces();
        exit(EXIT_SUCCESS);
    }

    // Parse command line arguments
    parseArguments(argc, argv, interface, &tcp, &udp, &port, &arp, &icmp4, &icmp6, &ndp, &igmp, &mld, &num);

    // Construct pcap filter
    constructFilter(pcap_filter, tcp, udp, port, arp, icmp4, icmp6, ndp, igmp, mld);

    // Open the network interface for capturing packets
    // From:
    // Using libpcap in C
    // https://www.devdungeon.com/content/using-libpcap-c
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open interface %s: %s\n", interface, error_buffer);
        exit(2);
    }

    // Check if interface provides Ethernet headers
    // From:
    // Programing with pcap
    // https://www.tcpdump.org/pcap.html
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
        exit(2);
    }

    // Compile and apply the pcap filter
    // From:
    // Programing with pcap
    // https://www.tcpdump.org/pcap.html
    struct bpf_program compiled_filter;
    if (pcap_compile(handle, &compiled_filter, pcap_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not compile filter %s: %s\n", pcap_filter, pcap_geterr(handle));
        exit(2);
    }

    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        fprintf(stderr, "Could not apply filter %s: %s\n", pcap_filter, pcap_geterr(handle));
        exit(2);
    }

    // Loop through packets and capture them
    // From:
    // Programing with pcap
    // https://www.tcpdump.org/pcap.html
    pcap_loop(handle, num, packetHandler, NULL);

    // Free memory and close handle
    pcap_freecode(&compiled_filter);
    pcap_close(handle);

    exit(EXIT_SUCCESS);
}