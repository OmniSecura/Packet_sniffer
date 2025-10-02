#ifndef PACKETHELPERS_H
#define PACKETHELPERS_H
#include "protocols/proto_struct.h"
#include <QMap>
#include <QVector>
#include <QString>
#include <arpa/inet.h>

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

inline int linkHdrLen(int linkType) {
    switch (linkType) {
        case DLT_LINUX_SLL:
            return LINUX_SLL_HEADER_LEN;
        default:
            return SIZE_ETHERNET;
    }
}

inline const sniff_linux_cooked* cookedHdr(const u_char* pkt) {
    return reinterpret_cast<const sniff_linux_cooked*>(pkt);
}

// Ethernet
inline const sniff_ethernet* ethHdr(const u_char* pkt) {
    return reinterpret_cast<const sniff_ethernet*>(pkt);
}
inline uint16_t ethType(const u_char* pkt, int linkType) {
    switch (linkType) {
        case DLT_LINUX_SLL:
            return ntohs(cookedHdr(pkt)->protocol);
        default:
            return ntohs(ethHdr(pkt)->ether_type);
    }
}

// ARP
inline const sniff_arp* arpHdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_arp*>(pkt + linkHdrLen(linkType));
}

// IPv4
inline const sniff_ip* ipv4Hdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_ip*>(pkt + linkHdrLen(linkType));
}
inline int ipv4HdrLen(const u_char* pkt, int linkType) {
    const auto ip = ipv4Hdr(pkt, linkType);
    return IP_HL(ip) * 4;
}
inline const u_char* ipv4Payload(const u_char* pkt, int linkType) {
    return pkt + linkHdrLen(linkType) + ipv4HdrLen(pkt, linkType);
}

// TCP
inline const sniff_tcp* tcpHdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_tcp*>(
        pkt + linkHdrLen(linkType) + ipv4HdrLen(pkt, linkType)
    );
}

// UDP
inline const sniff_udp* udpHdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_udp*>(
        pkt + linkHdrLen(linkType) + ipv4HdrLen(pkt, linkType)
    );
}

// ICMP
inline const sniff_icmp* icmpHdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_icmp*>(
        pkt + linkHdrLen(linkType) + ipv4HdrLen(pkt, linkType)
    );
}


// IPv6
inline const sniff_ipv6* ipv6Hdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_ipv6*>(pkt + linkHdrLen(linkType));
}
inline const u_char* ipv6Payload(const u_char* pkt, int linkType) {
    return pkt + linkHdrLen(linkType) + sizeof(sniff_ipv6);
}

inline const sniff_tcp* tcp6Hdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_tcp*>(
        pkt + linkHdrLen(linkType) + sizeof(sniff_ipv6)
    );
}

inline const sniff_udp* udp6Hdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_udp*>(
        pkt + linkHdrLen(linkType) + sizeof(sniff_ipv6)
    );
}

inline const sniff_icmpv6* icmp6Hdr(const u_char* pkt, int linkType) {
    return reinterpret_cast<const sniff_icmpv6*>(
        pkt + linkHdrLen(linkType) + sizeof(sniff_ipv6)
    );
}
// MAC → QString
inline QString macToStr(const u_char *a) {
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(a[0],2,16,QLatin1Char('0'))
        .arg(a[1],2,16,QLatin1Char('0'))
        .arg(a[2],2,16,QLatin1Char('0'))
        .arg(a[3],2,16,QLatin1Char('0'))
        .arg(a[4],2,16,QLatin1Char('0'))
        .arg(a[5],2,16,QLatin1Char('0'))
        .toUpper();
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
