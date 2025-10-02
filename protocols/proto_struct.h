#ifndef PROTO_STRUCT_H
#define PROTO_STRUCT_H

#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <string>
#include <netinet/in.h>

// -------------------------------------------------------------------------
// LINK LAYER
// -------------------------------------------------------------------------
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

struct sniff_ethernet {    // IEEE: 802.3
    u_char  ether_dhost[ETHER_ADDR_LEN];  // Destination MAC
    u_char  ether_shost[ETHER_ADDR_LEN];  // Source MAC
    u_short ether_type;                   // Ethertype (IP, ARP, VLAN, etc.)
};

struct sniff_dot1q {       // IEEE: 802.1Q
    u_short tci;         // Tag Control Info (VLAN ID, priority)
    u_short ether_type;  // Next Ethertype after VLAN
};

struct sniff_arp {         // RFC: 826
    u_short ar_hrd;
    u_short ar_pro;
    u_char  ar_hln;
    u_char  ar_pln;
    u_short ar_op;
    u_char  ar_sha[6];
    u_char  ar_sip[4];
    u_char  ar_tha[6];
    u_char  ar_tip[4];
};

// -------------------------------------------------------------------------
// NETWORK LAYER (IPv4 / IPv6 + ICMPs + IGMP + OSPF + BGP marker)
// -------------------------------------------------------------------------
struct sniff_ip {          // RFC: 791
    u_char  ip_vhl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

struct sniff_ipv6 {        // RFC: 8200
    uint32_t ip6_flow;
    uint16_t ip6_plen;
    uint8_t  ip6_nxt;
    uint8_t  ip6_hlim;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};

struct sniff_icmp {        // RFC: 792
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint16_t icmp_cksum;
    uint16_t icmp_id;
    uint16_t icmp_seq;
};

struct sniff_icmpv6 {      // RFC: 4443
    uint8_t  icmp6_type;
    uint8_t  icmp6_code;
    uint16_t icmp6_cksum;
    union {
        struct {
            uint16_t id;
            uint16_t seq;
        } echo;
        // other ICMPv6 message formats
    } icmp6_data;
};

// struct sniff_igmpv1v2 {    // RFC: 1112 (v1), RFC: 2236 (v2)
//     uint8_t  igmpv2_type;
//     uint8_t  igmpv2_mrt; // v1: always 0, v2: Max Resp Time in 1/10s sec
//     uint16_t igmpv2_cksum;
//     uint32_t igmpv2_ga;
// };

// struct sniff_igmpv3 {       // RFC: 3376
//     uint8_t  igmpv3_type;
//     uint8_t  igmpv3_mrc;
//     uint16_t igmpv3_cksum;
//     uint32_t igmpv3_ga;
//     uint8_t  igmpv3_flags;
//     uint8_t  igmpv3_qqic;
//     uint16_t igmpv3_nos;
//     struct in_addr[];  // group records (variable)
// };

struct sniff_ospf {        // RFC: 2328
    uint8_t  version;
    uint8_t  type;      // 1=Hello, 2=DB Description, 3=LS Request, 4=LS Update, 5=LS Ack
    uint16_t length;    // length of entire OSPF packet
    struct in_addr router_id;
    struct in_addr area_id;
    uint16_t checksum;  // standard IP-style checksum
    uint16_t autype;    // authentication type
    // then authentication data (8 bytes), and message-specific data
};

// struct sniff_rsvp {

// };

// struct sniff_pim {

// };

// // not commonly used nowadays
// struct sniff_egp{

// };

// struct sniff_pup{

// };

// struct sniff_idp{

// };

// struct sniff_tp{

// };

// struct sniff_mtp{

// };

// -------------------------------------------------------------------------
// TRANSPORT LAYER (TCP, UDP)
// -------------------------------------------------------------------------
typedef u_int tcp_seq;

struct sniff_tcp {         // RFC: 793
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char  th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};
// #define TH_OFF(th)  (((th)->th_offx2 & 0xF0) >> 4) //for options+padding and data

struct sniff_udp {         // RFC: 768
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
};

// -------------------------------------------------------------------------
// TUNNELING (GRE, IPv4-in-IPv4, L2TP, MPLS-in-IP, etc.)
// -------------------------------------------------------------------------
struct sniff_gre {         // RFC: 2784
    u_short flags_version;  // bits: C,R,K,S,etc. + version
    u_short protocol;       // Ethertype of encapsulated payload
    // optional fields if flags are set: checksum, key, sequence, etc.
};

// -------------------------------------------------------------------------
// IPsec (AH, ESP)
// -------------------------------------------------------------------------
struct sniff_ipsec_ah {    // RFC: 4302
    uint8_t  next_header;   // e.g. 6 for TCP, 17 for UDP
    uint8_t  payload_len;   // AH length in 32-bit words minus 2
    uint16_t reserved;
    uint32_t spi;           // Security Parameter Index
    uint32_t seq_no;        // Sequence number
    // variable Authentication Data
};

struct sniff_ipsec_esp {   // RFC: 4303
    uint32_t spi;     // Security Parameter Index
    uint32_t seq_no;  // Sequence number
    // Encrypted payload (variable), optional padding, etc.
};

// -------------------------------------------------------------------------
// BGP (Border Gateway Protocol)
// -------------------------------------------------------------------------
#define BGP_MARKER_LEN 16

struct sniff_bgp {         // RFC: 4271
    u_char marker[BGP_MARKER_LEN]; // Always 0xFF repeated
    u_short length;                // total length of BGP message
    u_char type;                   // 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE
    // Then variable payload depending on type
};

// -------------------------------------------------------------------------
// APPLICATION LAYER (DNS, DHCP)
// -------------------------------------------------------------------------
struct sniff_dns {         // RFC: 1035
    u_short id;
    u_short flags;
    u_short q_count;
    u_short ans_count;
    u_short auth_count;
    u_short add_count;
};

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN  64
#define DHCP_FILE_LEN   128

struct sniff_dhcp {        // RFC: 2131
    u_char  op;
    u_char  htype;
    u_char  hlen;
    u_char  hops;
    u_int   xid;
    u_short secs;
    u_short flags;
    u_int   ciaddr;
    u_int   yiaddr;
    u_int   siaddr;
    u_int   giaddr;
    u_char  chaddr[DHCP_CHADDR_LEN * 2];
    u_char  sname[DHCP_SNAME_LEN];
    u_char  file[DHCP_FILE_LEN];
    // Then variable DHCP options
};

#endif // PROTO_STRUCT_H
