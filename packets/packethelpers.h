#ifndef PACKETHELPERS_H
#define PACKETHELPERS_H
#include "protocols/proto_struct.h"
#include "sniffing.h" 
#include <QMap>
#include <QVector>
#include <QString>
#include <QStringList>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct sniff_linux_sll {
    uint16_t packet_type;
    uint16_t arphrd_type;
    uint16_t link_addr_len;
    uint8_t  link_addr[8];
    uint16_t protocol;
};

struct sniff_linux_sll2 {
    uint16_t protocol;
    uint16_t reserved;
    uint32_t if_index;
    uint16_t arphrd_type;
    uint8_t  packet_type;
    uint8_t  link_addr_len;
    uint8_t  link_addr[8];
    uint16_t reserved2;
};
#pragma pack(pop)

static_assert(sizeof(sniff_linux_sll)  == 16, "Unexpected SLL header size");
static_assert(sizeof(sniff_linux_sll2) == 20, "Unexpected SLL2 header size");

inline int linkHeaderLength(int datalinkType) {
    switch (datalinkType) {
        case DLT_EN10MB:
            return SIZE_ETHERNET;
        case DLT_LINUX_SLL:
            return static_cast<int>(sizeof(sniff_linux_sll));
        case DLT_LINUX_SLL2:
            return static_cast<int>(sizeof(sniff_linux_sll2));
        default:
            return SIZE_ETHERNET;
    }
}

inline uint16_t linkProtocol(const u_char* pkt, int datalinkType) {
    switch (datalinkType) {
        case DLT_EN10MB:
            return ntohs(reinterpret_cast<const sniff_ethernet*>(pkt)->ether_type);
        case DLT_LINUX_SLL:
            return ntohs(reinterpret_cast<const sniff_linux_sll*>(pkt)->protocol);
        case DLT_LINUX_SLL2:
            return ntohs(reinterpret_cast<const sniff_linux_sll2*>(pkt)->protocol);
        default:
            return ntohs(reinterpret_cast<const sniff_ethernet*>(pkt)->ether_type);
    }
}

inline const sniff_ethernet* ethHdr(const u_char* pkt, int datalinkType) {
    if (datalinkType == DLT_EN10MB)
        return reinterpret_cast<const sniff_ethernet*>(pkt);
    return nullptr;
}

inline const sniff_linux_sll* sllHdr(const u_char* pkt) {
    return reinterpret_cast<const sniff_linux_sll*>(pkt);
}

inline const sniff_linux_sll2* sll2Hdr(const u_char* pkt) {
    return reinterpret_cast<const sniff_linux_sll2*>(pkt);
}

// ARP
inline const sniff_arp* arpHdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_arp*>(pkt + linkHeaderLength(datalinkType));
}

// IPv4
inline const sniff_ip* ipv4Hdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_ip*>(pkt + linkHeaderLength(datalinkType));
}
inline int ipv4HdrLen(const u_char* pkt, int datalinkType) {
    const auto ip = ipv4Hdr(pkt, datalinkType);
    return IP_HL(ip) * 4;
}
inline const u_char* ipv4Payload(const u_char* pkt, int datalinkType) {
    return pkt + linkHeaderLength(datalinkType) + ipv4HdrLen(pkt, datalinkType);
}

// TCP
inline const sniff_tcp* tcpHdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_tcp*>(
        pkt + linkHeaderLength(datalinkType) + ipv4HdrLen(pkt, datalinkType)
    );
}

// UDP
inline const sniff_udp* udpHdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_udp*>(
        pkt + linkHeaderLength(datalinkType) + ipv4HdrLen(pkt, datalinkType)
    );
}

// ICMP
inline const sniff_icmp* icmpHdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_icmp*>(
        pkt + linkHeaderLength(datalinkType) + ipv4HdrLen(pkt, datalinkType)
    );
}

// IPv6
inline const sniff_ipv6* ipv6Hdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_ipv6*>(pkt + linkHeaderLength(datalinkType));
}
inline const u_char* ipv6Payload(const u_char* pkt, int datalinkType) {
    return pkt + linkHeaderLength(datalinkType) + sizeof(sniff_ipv6);
}

inline const sniff_tcp* tcp6Hdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_tcp*>(
        pkt + linkHeaderLength(datalinkType) + sizeof(sniff_ipv6)
    );
}

inline const sniff_udp* udp6Hdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_udp*>(
        pkt + linkHeaderLength(datalinkType) + sizeof(sniff_ipv6)
    );
}

inline const sniff_icmpv6* icmp6Hdr(const u_char* pkt, int datalinkType) {
    return reinterpret_cast<const sniff_icmpv6*>(
        pkt + linkHeaderLength(datalinkType) + sizeof(sniff_ipv6)
    );
}

inline QString macToStr(const u_char *a, int len = ETHER_ADDR_LEN) {
    QStringList parts;
    parts.reserve(len);
    for (int i = 0; i < len; ++i) {
        parts << QStringLiteral("%1").arg(a[i], 2, 16, QLatin1Char('0'));
    }
    return parts.join(QLatin1Char(':')).toUpper();
}

// IP proto name
inline QString protoName(uint8_t p) {
    QString proto;
    switch (p) {
        case IPPROTO_TCP:    proto = "TCP"; break;
        case IPPROTO_UDP:    proto = "UDP"; break;
        case IPPROTO_ICMP:   proto = "ICMP"; break;
        case IPPROTO_IGMP:   proto = "IGMP"; break;
        case IPPROTO_IPIP:   proto = "IPIP"; break;
        case IPPROTO_EGP:    proto = "EGP"; break;
        case IPPROTO_PUP:    proto = "PUP"; break;
        case IPPROTO_IDP:    proto = "IDP"; break;
        case IPPROTO_TP:     proto = "TP"; break;
        case IPPROTO_RSVP:   proto = "RSVP"; break;
        case IPPROTO_GRE:    proto = "GRE"; break;
        case IPPROTO_ESP:    proto = "ESP"; break;
        case IPPROTO_AH:     proto = "AH"; break;
        case IPPROTO_MTP:    proto = "MTP"; break;
        case IPPROTO_BEETPH: proto = "BEETPH"; break;
        case IPPROTO_ENCAP:  proto = "ENCAP"; break;
        case IPPROTO_PIM:    proto = "PIM"; break;
        case IPPROTO_COMP:   proto = "COMP"; break;
        case IPPROTO_L2TP:   proto = "L2TP"; break;
        case IPPROTO_SCTP:   proto = "SCTP"; break;
        case IPPROTO_UDPLITE:proto = "UDPLITE"; break;
        case IPPROTO_MPLS:   proto = "MPLS"; break;
        case IPPROTO_ICMPV6: proto = "ICMPv6"; break;
        case IPPROTO_HOPOPTS: proto = "HOPOPTS"; break;
        case IPPROTO_ROUTING: proto = "ROUTING"; break;
        case IPPROTO_FRAGMENT: proto = "FRAGMENT"; break;
        case IPPROTO_DSTOPTS: proto = "DSTOPTS"; break;
        case IPPROTO_NONE:    proto = "NONE"; break;
        case IPPROTO_MH:      proto = "MH"; break;
        default: return QString::number(p);
    }
    return proto;
}

//for my tree view
inline QMap<QString, QVector<ProtoField>>
groupByCategory(const QVector<ProtoField>& fields) {
    QMap<QString, QVector<ProtoField>> map;
    for (const auto &f : fields) {
        map[f.category].append(f);
    }
    return map;
}

#endif // PACKETHELPERS_H