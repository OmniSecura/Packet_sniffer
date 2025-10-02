#include "sniffing.h"
#include "packethelpers.h"
#include <ctype.h> 
#include <QMutexLocker>

Sniffing::Sniffing() {}
Sniffing::~Sniffing() {}

void Sniffing::packet_callback(u_char *args,
                               const pcap_pkthdr *header,
                               const u_char *packet)
{
    auto *worker = reinterpret_cast<PacketWorker*>(args);
    QByteArray raw(reinterpret_cast<const char*>(packet),
                   header->caplen);

    Sniffing::appendPacket(raw);

    QStringList infos;
    infos << QString::number(header->ts.tv_sec)
          << QString::number(header->caplen);

    emit worker->newPacket(raw, infos);
}


QString Sniffing::toHexAscii(const u_char *data, int len) const {
    QString out;
    int offset = 0;
    const int line_width = 16;

    while (offset < len) {
        int line_len = qMin(line_width, len - offset);
        const u_char *line = data + offset;

        // Offset
        out += QString("%1   ").arg(offset, 5, 10, QLatin1Char('0'));

        // Hex bytes
        for (int i = 0; i < line_len; ++i) {
            out += QString("%1 ").arg(line[i], 2, 16, QLatin1Char('0')).toUpper();
            if (i == 7) out += " ";
        }

        // Padding for shorter lines
        if (line_len < 8) out += " ";
        if (line_len < line_width) {
            out += QString((line_width - line_len) * 3 + 1, ' ');
        }

        // ASCII characters
        out += "   ";
        for (int i = 0; i < line_len; ++i) {
            char c = isprint(line[i]) ? line[i] : '.';
            out += QChar(c);
        }

        out += "\n";
        offset += line_len;
    }

    return out;
}

// --- simple summary for table ---
QStringList Sniffing::packetSummary(const u_char *packet,
                                    int total_len) const
{
    uint16_t ethertype = ethType(packet);
    QString src   = "-",
            dst   = "-",
            proto = "OTHER";

    if (ethertype == ETHERTYPE_IP) {
        auto ip  = ipv4Hdr(packet);

        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf));
        src = QString::fromLatin1(buf);
        inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf));
        dst = QString::fromLatin1(buf);
        switch (ip->ip_p) {
            case IPPROTO_TCP:    proto = "TCP";     break;
            case IPPROTO_UDP:    proto = "UDP";     break;
            case IPPROTO_ICMP:   proto = "ICMP";    break;
            case IPPROTO_IGMP:   proto = "IGMP";    break;
            case IPPROTO_IPIP:   proto = "IPIP";    break;
            case IPPROTO_EGP:    proto = "EGP";     break;
            case IPPROTO_PUP:    proto = "PUP";     break;
            case IPPROTO_IDP:    proto = "IDP";     break;
            case IPPROTO_TP:     proto = "TP";      break;
            case IPPROTO_RSVP:   proto = "RSVP";    break;
            case IPPROTO_GRE:    proto = "GRE";     break;
            case IPPROTO_ESP:    proto = "ESP";     break;
            case IPPROTO_AH:     proto = "AH";      break;
            case IPPROTO_MTP:    proto = "MTP";     break;
            case IPPROTO_BEETPH: proto = "BEETPH";  break;
            case IPPROTO_ENCAP:  proto = "ENCAP";   break;
            case IPPROTO_PIM:    proto = "PIM";     break;
            case IPPROTO_COMP:   proto = "COMP";    break;
            case IPPROTO_L2TP:   proto = "L2TP";    break;
            case IPPROTO_SCTP:   proto = "SCTP";    break;
            case IPPROTO_UDPLITE:proto = "UDPLITE"; break;
            case IPPROTO_MPLS:   proto = "MPLS";    break;
            case 89:             proto = "OSPF";    break;  
            case 41:             proto = "IPv6";    break;  // IPv6-in-IPv4
            default:             proto = "OTHER";   break;
        }
    }
    else if (ethertype == ETHERTYPE_ARP) {
      auto arpData = parseArp(packet);
      return { arpData[0], arpData[1], "ARP", QString::number(total_len) };
    }
    else if (ethertype == ETHERTYPE_IPV6) {
        auto ip6 = ipv6Hdr(packet);

        char buf6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof(buf6));
        src = QString::fromLatin1(buf6);
        inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof(buf6));
        dst = QString::fromLatin1(buf6);

        switch (ip6->ip6_nxt) {
            case IPPROTO_TCP:      proto = "TCP";      break;
            case IPPROTO_UDP:      proto = "UDP";      break;
            case IPPROTO_ICMPV6:   proto = "ICMPv6";   break;
            case IPPROTO_HOPOPTS:  proto = "HOPOPTS";  break;
            case IPPROTO_ROUTING:  proto = "ROUTING";  break;
            case IPPROTO_FRAGMENT: proto = "FRAGMENT"; break;
            case IPPROTO_AH:       proto = "AH";       break;
            case IPPROTO_ESP:      proto = "ESP";      break;
            case IPPROTO_DSTOPTS:  proto = "DSTOPTS";  break;
            case IPPROTO_NONE:     proto = "NONE";     break;
            case IPPROTO_MH:       proto = "MH";       break;
            case IPPROTO_SCTP:     proto = "SCTP";     break;   
            case IPPROTO_UDPLITE:  proto = "UDPLITE";  break;
            case IPPROTO_PIM:      proto = "PIM";      break;
            case IPPROTO_RSVP:     proto = "RSVP";     break;
            default:               proto = "OTHER";    break;
        }
    }

    QString len = QString::number(total_len);

    return { src, dst, proto, len };
}

QStringList Sniffing::parseArp(const u_char *pkt) const {
    auto arp = arpHdr(pkt);

    in_addr sip{}, tip{};
    memcpy(&sip, arp->ar_sip, 4);
    memcpy(&tip, arp->ar_tip, 4);

    QString hrd   = QString::number(ntohs(arp->ar_hrd));
    QString pro   = QString::number(ntohs(arp->ar_pro));
    QString hln   = QString::number(arp->ar_hln);
    QString pln   = QString::number(arp->ar_pln);
    QString op    = (ntohs(arp->ar_op)==1 ? "Request" : "Reply");
    QString sha   = macToStr(arp->ar_sha);
    QString tha   = macToStr(arp->ar_tha);
    QString sipStr = QString::fromUtf8(inet_ntoa(sip));
    QString tipStr = QString::fromUtf8(inet_ntoa(tip));

    return { sipStr, tipStr, hrd, pro, hln, pln, op, sha, tha};
}

QStringList Sniffing::parseTcp(const u_char *pkt) const {
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);
    
    const sniff_tcp *tcp = nullptr;
    char buf6[INET6_ADDRSTRLEN];
    char buf[INET_ADDRSTRLEN];

    QString src, dst;
    if (ethertype == ETHERTYPE_IP){
        auto ip = ipv4Hdr(pkt);
        tcp = tcpHdr(pkt);
        inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf));
            src = QString::fromLatin1(buf);
        inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf));
            dst = QString::fromLatin1(buf);
    }
    else if (ethertype == ETHERTYPE_IPV6) {
        auto ip6 = ipv6Hdr(pkt);
        tcp = tcp6Hdr(pkt);
        inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof(buf6));
            src = QString::fromLatin1(buf6);
        inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof(buf6));
            dst = QString::fromLatin1(buf6);
    } else {
        return {};
    }

    quint16 sport = ntohs(tcp->th_sport);
    quint16 dport = ntohs(tcp->th_dport);
    quint32 seq   = ntohl(tcp->th_seq);
    quint32 ack   = ntohl(tcp->th_ack);
    quint16 win = ntohs(tcp->th_win);
    quint16 sum = ntohs(tcp->th_sum);
    quint16 urp = ntohs(tcp->th_urp);
    int tcpHeaderLenWords = TH_OFF(tcp);    
    int tcpHeaderLenBytes = tcpHeaderLenWords * 4;

    QStringList flagsList;
    quint8 flags = tcp->th_flags;
    if (flags & TH_FIN)  flagsList << "FIN";
    if (flags & TH_SYN)  flagsList << "SYN";
    if (flags & TH_RST)  flagsList << "RST";
    if (flags & TH_PUSH) flagsList << "PSH";
    if (flags & TH_ACK)  flagsList << "ACK";
    if (flags & TH_URG)  flagsList << "URG";
    if (flags & TH_ECE)  flagsList << "ECE";
    if (flags & TH_CWR)  flagsList << "CWR";
    QString flagsStr = flagsList.join("|");

    QStringList out;
    out << src
        << dst
        << QString::number(sport)
        << QString::number(dport)
        << QString::number(seq)
        << QString::number(ack)
        << QString::number(tcpHeaderLenBytes)
        << flagsStr
        << QString::number(win)
        << QString::number(sum)
        << QString::number(urp);
    return out;
}

QStringList Sniffing::parseUdp(const u_char *pkt) const {
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    const sniff_udp *udp = nullptr;
    char buf[INET_ADDRSTRLEN];
    char buf6[INET6_ADDRSTRLEN];
    QString src, dst;
    if (ethertype == ETHERTYPE_IP){
        auto ip = ipv4Hdr(pkt);
        udp = udpHdr(pkt);
        if (inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf)))
            src = QString::fromLatin1(buf);
        if (inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf)))
            dst = QString::fromLatin1(buf);
    }
    else if (ethertype == ETHERTYPE_IPV6){
        auto ip6 = ipv6Hdr(pkt);
        udp = udp6Hdr(pkt);
        if (inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof(buf6)))
            src = QString::fromLatin1(buf6);
        if (inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof(buf6)))
            dst = QString::fromLatin1(buf6);
    } else {
        return {};
    }

    quint16 sport = ntohs(udp->uh_sport);
    quint16 dport = ntohs(udp->uh_dport);
    quint32 len   = ntohs(udp->uh_len);
    quint32 sum   = ntohs(udp->uh_sum);

    QStringList out;
    out << src
        << dst
        << QString::number(sport)
        << QString::number(dport)
        << QString::number(len)
        << QString::number(sum);
    return out;
}

QStringList Sniffing::parseIcmp(const u_char *pkt) const {
    auto icmp = icmpHdr(pkt);
    QString message;
    uint8_t type = icmp->icmp_type;
    uint8_t code = icmp->icmp_code;

    uint16_t checksum = icmp->icmp_cksum;
    uint16_t identifier = ntohs(icmp->icmp_id);
    uint16_t sequence = ntohs(icmp->icmp_seq);

    switch (type) {
        case 0: message = "Echo Reply"; break;
        case 3:
            message = "Destination Unreachable";
            switch (code) {
                case 0: message += " (Network Unreachable)"; break;
                case 1: message += " (Host Unreachable)"; break;
                case 2: message += " (Protocol Unreachable)"; break;
                case 3: message += " (Port Unreachable)"; break;
                case 4: message += " (Fragmentation Needed and DF set)"; break;
                case 5: message += " (Source Route Failed)"; break;
                case 6: message += " (Destination Network Unknown)"; break;
                case 7: message += " (Destination Host Unknown)"; break;
                case 8: message += " (Source Host Isolated)"; break;
                case 9: message += " (Network Administratively Prohibited)"; break;
                case 10: message += " (Host Administratively Prohibited)"; break;
                case 11: message += " (Network Unreachable for ToS)"; break;
                case 12: message += " (Host Unreachable for ToS)"; break;
                case 13: message += " (Communication Administratively Prohibited)"; break;
                case 14: message += " (Host Precedence Violation)"; break;
                case 15: message += " (Precedence Cutoff in Effect)"; break;
            }
            break;
        case 4: message = "Source Quench (Deprecated)"; break;
        case 5:
            message = "Redirect";
            switch (code) {
                case 0: message += " (Redirect Datagram for the Network)"; break;
                case 1: message += " (Redirect Datagram for the Host)"; break;
                case 2: message += " (Redirect for ToS & Network)"; break;
                case 3: message += " (Redirect for ToS & Host)"; break;
            }
            break;
        case 8: message = "Echo Request"; break;
        case 9: message = "Router Advertisement"; break;
        case 10: message = "Router Solicitation"; break;
        case 11:
            message = "Time Exceeded";
            switch (code) {
                case 0: message += " (TTL Exceeded in Transit)"; break;
                case 1: message += " (Fragment Reassembly Time Exceeded)"; break;
            }
            break;
        case 12:
            message = "Parameter Problem";
            switch (code) {
                case 0: message += " (Pointer indicates error)"; break;
                case 1: message += " (Missing required option)"; break;
                case 2: message += " (Bad length)"; break;
            }
            break;
        case 13: message = "Timestamp Request"; break;
        case 14: message = "Timestamp Reply"; break;
        case 15: message = "Information Request (Deprecated)"; break;
        case 16: message = "Information Reply (Deprecated)"; break;
        case 17: message = "Address Mask Request"; break;
        case 18: message = "Address Mask Reply"; break;
        case 30: message = "Traceroute (Deprecated)"; break;
        default: message = "Unknown or Reserved"; break;
    }

    
    QStringList out;
    out << QString::number(type)
        << QString::number(code)
        << QStringLiteral("0x%1")
             .arg(checksum, 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(identifier)
        << QString::number(sequence)
        << message;

    return out;
}

QStringList Sniffing::parseIcmpv6(const u_char *pkt) const {
    auto icmp6 = icmp6Hdr(pkt);
    if (!icmp6) return {};

    uint8_t type = icmp6->icmp6_type;
    uint8_t code = icmp6->icmp6_code;
    uint16_t checksum = ntohs(icmp6->icmp6_cksum);

    QString message;
    switch (type) {
        case 1:  message = "Destination Unreachable"; break;
        case 2:  message = "Packet Too Big"; break;
        case 3:  message = "Time Exceeded"; break;
        case 4:  message = "Parameter Problem"; break;
        case 128: message = "Echo Request"; break;
        case 129: message = "Echo Reply"; break;
        case 130: message = "Multicast Listener Query"; break;
        case 131: message = "Multicast Listener Report"; break;
        case 132: message = "Multicast Listener Done"; break;
        case 133: message = "Router Solicitation"; break;
        case 134: message = "Router Advertisement"; break;
        case 135: message = "Neighbor Solicitation"; break;
        case 136: message = "Neighbor Advertisement"; break;
        case 137: message = "Redirect"; break;
        default: message = "Unknown"; break;
    }

    uint16_t identifier = 0;
    uint16_t sequence   = 0;
    if (type == 128 || type == 129) {
        identifier = ntohs(icmp6->icmp6_data.echo.id);
        sequence   = ntohs(icmp6->icmp6_data.echo.seq);
    }

    QStringList out;
    out << QString::number(type)
        << QString::number(code)
        << QStringLiteral("0x%1").arg(checksum, 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(identifier)
        << QString::number(sequence)
        << message;

    return out;
}

QStringList Sniffing::parseIgmp(const u_char *pkt) const {
    auto igmp = reinterpret_cast<const sniff_igmpv1v2*>(ipv4Payload(pkt));
    if (!igmp) return {};

    uint8_t type = igmp->type;
    QString typeName;
    switch (type) {
        case 0x11: typeName = "Membership Query"; break;
        case 0x12: typeName = "Membership Report v1"; break;
        case 0x16: typeName = "Membership Report v2"; break;
        case 0x17: typeName = "Leave Group"; break;
        default:   typeName = "Unknown"; break;
    }

    QString groupAddr = QString::fromLatin1(inet_ntoa(igmp->group_addr));

    QStringList out;
    out << QString::number(type)
        << typeName
        << QString::number(igmp->mrt)
        << QStringLiteral("0x%1").arg(ntohs(igmp->cksum), 4, 16, QLatin1Char('0')).toUpper()
        << groupAddr;

    return out;
}

QStringList Sniffing::parseSctp(const u_char *pkt) const {
    const sniff_sctp *sctp = nullptr;
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    if (ethertype == ETHERTYPE_IP) {
        sctp = reinterpret_cast<const sniff_sctp*>(ipv4Payload(pkt));
    } else if (ethertype == ETHERTYPE_IPV6) {
        sctp = reinterpret_cast<const sniff_sctp*>(ipv6Payload(pkt));
    } else {
        return {};
    }

    if (!sctp) return {};

    QStringList out;
    out << QString::number(ntohs(sctp->src_port))
        << QString::number(ntohs(sctp->dst_port))
        << QStringLiteral("0x%1").arg(ntohl(sctp->verification_tag), 8, 16, QLatin1Char('0')).toUpper()
        << QStringLiteral("0x%1").arg(ntohl(sctp->checksum), 8, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseUdplite(const u_char *pkt) const {
    const sniff_udplite *udplite = nullptr;
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    if (ethertype == ETHERTYPE_IP) {
        udplite = reinterpret_cast<const sniff_udplite*>(ipv4Payload(pkt));
    } else if (ethertype == ETHERTYPE_IPV6) {
        udplite = reinterpret_cast<const sniff_udplite*>(ipv6Payload(pkt));
    } else {
        return {};
    }

    if (!udplite) return {};

    QStringList out;
    out << QString::number(ntohs(udplite->src_port))
        << QString::number(ntohs(udplite->dst_port))
        << QString::number(ntohs(udplite->checksum_cov))
        << QStringLiteral("0x%1").arg(ntohs(udplite->checksum), 4, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseGre(const u_char *pkt) const {
    const sniff_gre *gre = nullptr;
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    if (ethertype == ETHERTYPE_IP) {
        gre = reinterpret_cast<const sniff_gre*>(ipv4Payload(pkt));
    } else if (ethertype == ETHERTYPE_IPV6) {
        gre = reinterpret_cast<const sniff_gre*>(ipv6Payload(pkt));
    } else {
        return {};
    }

    if (!gre) return {};

    uint16_t flagsVersion = ntohs(gre->flags_version);
    uint16_t protocol     = ntohs(gre->protocol);
    uint8_t version       = flagsVersion & 0x7;

    QStringList out;
    out << QStringLiteral("0x%1").arg(flagsVersion, 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(version)
        << QStringLiteral("0x%1").arg(protocol, 4, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseOspf(const u_char *pkt) const {
    auto ospf = reinterpret_cast<const sniff_ospf*>(ipv4Payload(pkt));
    if (!ospf) return {};

    QStringList out;
    out << QString::number(ospf->version)
        << QString::number(ospf->type)
        << QString::number(ntohs(ospf->length))
        << QString::fromLatin1(inet_ntoa(ospf->router_id))
        << QString::fromLatin1(inet_ntoa(ospf->area_id))
        << QStringLiteral("0x%1").arg(ntohs(ospf->checksum), 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(ntohs(ospf->autype));

    return out;
}

QStringList Sniffing::parseRsvp(const u_char *pkt) const {
    const sniff_rsvp *rsvp = nullptr;
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    if (ethertype == ETHERTYPE_IP) {
        rsvp = reinterpret_cast<const sniff_rsvp*>(ipv4Payload(pkt));
    } else if (ethertype == ETHERTYPE_IPV6) {
        rsvp = reinterpret_cast<const sniff_rsvp*>(ipv6Payload(pkt));
    } else {
        return {};
    }

    if (!rsvp) return {};

    QStringList out;
    out << QString::number(rsvp->ver_flags >> 4)
        << QString::number(rsvp->msg_type)
        << QStringLiteral("0x%1").arg(ntohs(rsvp->checksum), 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(rsvp->send_ttl)
        << QString::number(ntohs(rsvp->length));

    return out;
}

QStringList Sniffing::parsePim(const u_char *pkt) const {
    const sniff_pim *pim = nullptr;
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    if (ethertype == ETHERTYPE_IP) {
        pim = reinterpret_cast<const sniff_pim*>(ipv4Payload(pkt));
    } else if (ethertype == ETHERTYPE_IPV6) {
        pim = reinterpret_cast<const sniff_pim*>(ipv6Payload(pkt));
    } else {
        return {};
    }

    if (!pim) return {};

    uint8_t version = pim->ver_type >> 4;
    uint8_t type    = pim->ver_type & 0x0F;

    QStringList out;
    out << QString::number(version)
        << QString::number(type)
        << QStringLiteral("0x%1").arg(ntohs(pim->checksum), 4, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseEgp(const u_char *pkt) const {
    auto egp = reinterpret_cast<const sniff_egp*>(ipv4Payload(pkt));
    if (!egp) return {};

    QStringList out;
    out << QString::number(egp->version)
        << QString::number(egp->type)
        << QString::number(egp->code)
        << QString::number(egp->status)
        << QStringLiteral("0x%1").arg(ntohs(egp->checksum), 4, 16, QLatin1Char('0')).toUpper()
        << QString::number(ntohs(egp->autonomous_system))
        << QString::number(ntohs(egp->sequence));

    return out;
}

QStringList Sniffing::parseAh(const u_char *pkt) const {
    const sniff_ipsec_ah *ah = nullptr;
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    if (ethertype == ETHERTYPE_IP) {
        ah = reinterpret_cast<const sniff_ipsec_ah*>(ipv4Payload(pkt));
    } else if (ethertype == ETHERTYPE_IPV6) {
        ah = reinterpret_cast<const sniff_ipsec_ah*>(ipv6Payload(pkt));
    } else {
        return {};
    }

    if (!ah) return {};

    QStringList out;
    out << QString::number(ah->next_header)
        << QString::number(ah->payload_len)
        << QStringLiteral("0x%1").arg(ntohl(ah->spi), 8, 16, QLatin1Char('0')).toUpper()
        << QString::number(ntohl(ah->seq_no));

    return out;
}

QStringList Sniffing::parseEsp(const u_char *pkt) const {
    const sniff_ipsec_esp *esp = nullptr;
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    if (ethertype == ETHERTYPE_IP) {
        esp = reinterpret_cast<const sniff_ipsec_esp*>(ipv4Payload(pkt));
    } else if (ethertype == ETHERTYPE_IPV6) {
        esp = reinterpret_cast<const sniff_ipsec_esp*>(ipv6Payload(pkt));
    } else {
        return {};
    }

    if (!esp) return {};

    QStringList out;
    out << QStringLiteral("0x%1").arg(ntohl(esp->spi), 8, 16, QLatin1Char('0')).toUpper()
        << QString::number(ntohl(esp->seq_no));

    return out;
}

QStringList Sniffing::parseMpls(const u_char *pkt) const {
    const sniff_mpls *mpls = nullptr;
    auto eth = ethHdr(pkt);
    uint16_t ethertype = ntohs(eth->ether_type);

    if (ethertype == ETHERTYPE_IP) {
        mpls = reinterpret_cast<const sniff_mpls*>(ipv4Payload(pkt));
    } else if (ethertype == ETHERTYPE_IPV6) {
        mpls = reinterpret_cast<const sniff_mpls*>(ipv6Payload(pkt));
    } else {
        return {};
    }

    if (!mpls) return {};

    uint32_t entry = ntohl(mpls->label_stack_entry);
    uint32_t label = entry >> 12;
    uint8_t tc     = (entry >> 9) & 0x07;
    uint8_t s      = (entry >> 8) & 0x01;
    uint8_t ttl    = entry & 0xFF;

    QStringList out;
    out << QString::number(label)
        << QString::number(tc)
        << QString::number(s)
        << QString::number(ttl);

    return out;
}

QStringList Sniffing::parseIpip(const u_char *pkt) const {
    auto innerIp = reinterpret_cast<const sniff_ip*>(ipv4Payload(pkt));
    if (!innerIp) return {};

    QStringList out;
    out << QString::fromLatin1(inet_ntoa(innerIp->ip_src))
        << QString::fromLatin1(inet_ntoa(innerIp->ip_dst))
        << QString::number(innerIp->ip_p)
        << QString::number(ntohs(innerIp->ip_len));

    return out;
}

QStringList Sniffing::parseIpv6HopByHop(const u_char *pkt) const {
    auto hop = reinterpret_cast<const sniff_ipv6_hopopts*>(ipv6Payload(pkt));
    if (!hop) return {};

    QStringList out;
    out << QString::number(hop->next_header)
        << protoName(hop->next_header)
        << QString::number(hop->hdr_ext_len);

    return out;
}

QStringList Sniffing::parseIpv6Routing(const u_char *pkt) const {
    auto routing = reinterpret_cast<const sniff_ipv6_routing*>(ipv6Payload(pkt));
    if (!routing) return {};

    QStringList out;
    out << QString::number(routing->next_header)
        << protoName(routing->next_header)
        << QString::number(routing->routing_type)
        << QString::number(routing->segments_left);

    return out;
}

QStringList Sniffing::parseIpv6Fragment(const u_char *pkt) const {
    auto frag = reinterpret_cast<const sniff_ipv6_fragment*>(ipv6Payload(pkt));
    if (!frag) return {};

    uint16_t offsetField = ntohs(frag->frag_offset);
    uint16_t offset = (offsetField >> 3) & 0x1FFF;
    bool moreFragments = offsetField & 0x1;

    QStringList out;
    out << QString::number(frag->next_header)
        << protoName(frag->next_header)
        << QString::number(offset)
        << (moreFragments ? "Yes" : "No")
        << QStringLiteral("0x%1").arg(ntohl(frag->identification), 8, 16, QLatin1Char('0')).toUpper();

    return out;
}

QStringList Sniffing::parseIpv6Destination(const u_char *pkt) const {
    auto dest = reinterpret_cast<const sniff_ipv6_dstopts*>(ipv6Payload(pkt));
    if (!dest) return {};

    QStringList out;
    out << QString::number(dest->next_header)
        << protoName(dest->next_header)
        << QString::number(dest->hdr_ext_len);

    return out;
}

QStringList Sniffing::parseIpv6Mobility(const u_char *pkt) const {
    auto mobility = reinterpret_cast<const sniff_ipv6_mobility*>(ipv6Payload(pkt));
    if (!mobility) return {};

    QStringList out;
    out << QString::number(mobility->next_header)
        << protoName(mobility->next_header)
        << QString::number(mobility->mh_type)
        << QStringLiteral("0x%1").arg(ntohs(mobility->checksum), 4, 16, QLatin1Char('0')).toUpper();

    return out;
}


QVector<PacketLayer> Sniffing::parseLayers(const u_char* pkt) const {
    QVector<PacketLayer> layers;
    ProtoField field;

    // --- Ethernet II ---
    const auto eth = ethHdr(pkt);
    PacketLayer ethLayer;
    ethLayer.name = "Ethernet II";

    field.category = "Frame Header";
    field.label    = "Src";
    field.value    = macToStr(eth->ether_shost);
    ethLayer.fields.append(field);

    field.label    = "Dst";
    field.value    = macToStr(eth->ether_dhost);
    ethLayer.fields.append(field);

    field.label    = "Type";
    field.value    = QString("0x%1")
                     .arg(ntohs(eth->ether_type), 4, 16, QChar('0'));
    ethLayer.fields.append(field);

    layers.append(ethLayer);

    uint16_t et = ethType(pkt);

    // --- IPv4 ---
    if (et == ETHERTYPE_IP) {
        const auto ip = ipv4Hdr(pkt);
        PacketLayer ipLayer;
        ipLayer.name = "Internet Protocol Version 4";

        field.category = "IP Header";
        field.label    = "Src";
        field.value    = QString::fromLatin1(inet_ntoa(ip->ip_src));
        ipLayer.fields.append(field);

        field.label    = "Dst";
        field.value    = QString::fromLatin1(inet_ntoa(ip->ip_dst));
        ipLayer.fields.append(field);

        field.label    = "Protocol";
        field.value    = protoName(ip->ip_p);
        ipLayer.fields.append(field);

        layers.append(ipLayer);

        // --- TCP ---
        if (ip->ip_p == IPPROTO_TCP) {
            auto vals = parseTcp(pkt);
            static const QStringList labels = {
                "Sender IP","Target IP","Source port","Destination port",
                "Sequence number","ACK number","TCP header length","Flags",
                "Window size","Checksum","Urgent pointer"
            };
            PacketLayer tcpLayer;
            tcpLayer.name = "Transmission Control Protocol";

            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                // different category for flags
                if (labels[i] == "Sender IP" ||
                    labels[i] == "Target IP" ||
                    labels[i] == "Source port" ||
                    labels[i] == "Destination port")
                {
                    field.category = "Connection";
                }
                else if (labels[i] == "Sequence number" ||
                        labels[i] == "ACK number")
                {
                    field.category = "Sequence";
                }
                else {
                    field.category = "Control";
                }
                field.label    = labels[i];
                field.value    = vals[i];
                tcpLayer.fields.append(field);
            }
            layers.append(tcpLayer);
        }
        // --- UDP ---
        else if (ip->ip_p == IPPROTO_UDP) {
            auto vals = parseUdp(pkt);
            static const QStringList labels = {
                "Sender IP","Target IP","Source port","Destination port",
                "Length","Checksum"
            };
            PacketLayer udpLayer;
            udpLayer.name = "User Datagram Protocol";
            field.category = "UDP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                udpLayer.fields.append(field);
            }
            layers.append(udpLayer);
        }
        // --- ICMPv4 ---
        else if (ip->ip_p == IPPROTO_ICMP) {
            auto vals = parseIcmp(pkt);
            static const QStringList labels = {
                "ICMPv4 Type","Code","Checksum","Identifier",
                "Sequence","Message"
            };
            PacketLayer icmpLayer;
            icmpLayer.name = "Internet Control Message Protocol";
            field.category = "ICMP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                icmpLayer.fields.append(field);
            }
            layers.append(icmpLayer);
        }
        // --- IGMP ---
        else if (ip->ip_p == IPPROTO_IGMP) {
            auto vals = parseIgmp(pkt);
            static const QStringList labels = {
                "Type","Description","Max Response Time","Checksum","Group Address"
            };
            PacketLayer igmpLayer;
            igmpLayer.name = "Internet Group Management Protocol";
            field.category = "IGMP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                igmpLayer.fields.append(field);
            }
            layers.append(igmpLayer);
        }
        // --- SCTP ---
        else if (ip->ip_p == IPPROTO_SCTP) {
            auto vals = parseSctp(pkt);
            static const QStringList labels = {
                "Source port","Destination port","Verification Tag","Checksum"
            };
            PacketLayer sctpLayer;
            sctpLayer.name = "Stream Control Transmission Protocol";
            field.category = "SCTP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                sctpLayer.fields.append(field);
            }
            layers.append(sctpLayer);
        }
        // --- UDP-Lite ---
        else if (ip->ip_p == IPPROTO_UDPLITE) {
            auto vals = parseUdplite(pkt);
            static const QStringList labels = {
                "Source port","Destination port","Checksum coverage","Checksum"
            };
            PacketLayer udpliteLayer;
            udpliteLayer.name = "UDP-Lite";
            field.category = "UDP-Lite Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                udpliteLayer.fields.append(field);
            }
            layers.append(udpliteLayer);
        }
        // --- GRE ---
        else if (ip->ip_p == IPPROTO_GRE) {
            auto vals = parseGre(pkt);
            static const QStringList labels = {
                "Flags","Version","Protocol"
            };
            PacketLayer greLayer;
            greLayer.name = "Generic Routing Encapsulation";
            field.category = "GRE Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                greLayer.fields.append(field);
            }
            layers.append(greLayer);
        }
        // --- IP-in-IP ---
        else if (ip->ip_p == IPPROTO_IPIP) {
            auto vals = parseIpip(pkt);
            static const QStringList labels = {
                "Inner Src","Inner Dst","Inner Protocol","Inner Length"
            };
            PacketLayer ipipLayer;
            ipipLayer.name = "IP in IP";
            field.category = "Inner IPv4";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                ipipLayer.fields.append(field);
            }
            layers.append(ipipLayer);
        }
        // --- OSPF ---
        else if (ip->ip_p == IPPROTO_OSPFIGP) {
            auto vals = parseOspf(pkt);
            static const QStringList labels = {
                "Version","Type","Length","Router ID","Area ID","Checksum","Auth Type"
            };
            PacketLayer ospfLayer;
            ospfLayer.name = "Open Shortest Path First";
            field.category = "OSPF Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                ospfLayer.fields.append(field);
            }
            layers.append(ospfLayer);
        }
        // --- RSVP ---
        else if (ip->ip_p == IPPROTO_RSVP) {
            auto vals = parseRsvp(pkt);
            static const QStringList labels = {
                "Version","Message Type","Checksum","Send TTL","Length"
            };
            PacketLayer rsvpLayer;
            rsvpLayer.name = "Resource Reservation Protocol";
            field.category = "RSVP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                rsvpLayer.fields.append(field);
            }
            layers.append(rsvpLayer);
        }
        // --- PIM ---
        else if (ip->ip_p == IPPROTO_PIM) {
            auto vals = parsePim(pkt);
            static const QStringList labels = {
                "Version","Message Type","Checksum"
            };
            PacketLayer pimLayer;
            pimLayer.name = "Protocol Independent Multicast";
            field.category = "PIM Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                pimLayer.fields.append(field);
            }
            layers.append(pimLayer);
        }
        // --- EGP ---
        else if (ip->ip_p == IPPROTO_EGP) {
            auto vals = parseEgp(pkt);
            static const QStringList labels = {
                "Version","Type","Code","Status","Checksum","AS Number","Sequence"
            };
            PacketLayer egpLayer;
            egpLayer.name = "Exterior Gateway Protocol";
            field.category = "EGP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                egpLayer.fields.append(field);
            }
            layers.append(egpLayer);
        }
        // --- IPsec AH ---
        else if (ip->ip_p == IPPROTO_AH) {
            auto vals = parseAh(pkt);
            static const QStringList labels = {
                "Next Header","Payload Length","SPI","Sequence Number"
            };
            PacketLayer ahLayer;
            ahLayer.name = "Authentication Header";
            field.category = "AH Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                ahLayer.fields.append(field);
            }
            layers.append(ahLayer);
        }
        // --- IPsec ESP ---
        else if (ip->ip_p == IPPROTO_ESP) {
            auto vals = parseEsp(pkt);
            static const QStringList labels = {
                "SPI","Sequence Number"
            };
            PacketLayer espLayer;
            espLayer.name = "Encapsulating Security Payload";
            field.category = "ESP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                espLayer.fields.append(field);
            }
            layers.append(espLayer);
        }
        // --- MPLS-in-IP ---
        else if (ip->ip_p == IPPROTO_MPLS) {
            auto vals = parseMpls(pkt);
            static const QStringList labels = {
                "Label","Traffic Class","Bottom of Stack","TTL"
            };
            PacketLayer mplsLayer;
            mplsLayer.name = "Multiprotocol Label Switching";
            field.category = "MPLS Entry";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                mplsLayer.fields.append(field);
            }
            layers.append(mplsLayer);
        }
    }
    // --- IPv6 ---
    else if (et == ETHERTYPE_IPV6) {
        const auto ip6 = ipv6Hdr(pkt);
        PacketLayer ip6Layer;
        ip6Layer.name = "Internet Protocol Version 6";

        char buf6[INET6_ADDRSTRLEN];
        field.category = "IP Header";
        field.label    = "Src";
        field.value    = QString::fromLatin1(
                           inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof(buf6))
                        );
        ip6Layer.fields.append(field);

        field.label    = "Dst";
        field.value    = QString::fromLatin1(
                           inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof(buf6))
                        );
        ip6Layer.fields.append(field);

        field.label    = "Next Header";
        field.value    = protoName(ip6->ip6_nxt);
        ip6Layer.fields.append(field);

        layers.append(ip6Layer);

        // --- TCP ---
        if (ip6->ip6_nxt == IPPROTO_TCP) {
            auto vals = parseTcp(pkt);
            static const QStringList labels = {
                "Sender IP","Target IP","Source port","Destination port",
                "Sequence number","ACK number","TCP header length","Flags",
                "Window size","Checksum","Urgent pointer"
            };
            PacketLayer tcp6Layer;
            tcp6Layer.name = "Transmission Control Protocol";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.category = (labels[i] == "Flags"
                                  ? "Flags"
                                  : "TCP Header");
                field.label    = labels[i];
                field.value    = vals[i];
                tcp6Layer.fields.append(field);
            }
            layers.append(tcp6Layer);
        }
        // --- UDP ---
        else if (ip6->ip6_nxt == IPPROTO_UDP) {
            auto vals = parseUdp(pkt);
            static const QStringList labels = {
                "Sender IP","Target IP","Source port","Destination port",
                "Length","Checksum"
            };
            PacketLayer udp6Layer;
            udp6Layer.name = "User Datagram Protocol";
            field.category = "UDP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                udp6Layer.fields.append(field);
            }
            layers.append(udp6Layer);
        }
        // --- ICMPv6 ---
        else if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
            auto vals = parseIcmpv6(pkt);
            static const QStringList labels = {
                "ICMPv6 Type","Code","Checksum","Identifier","Sequence","Message"
            };
            PacketLayer icmp6Layer;
            icmp6Layer.name = "Internet Control Message Protocol v6";
            field.category = "ICMPv6 Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                icmp6Layer.fields.append(field);
            }
            layers.append(icmp6Layer);
        }
        // --- SCTP ---
        else if (ip6->ip6_nxt == IPPROTO_SCTP) {
            auto vals = parseSctp(pkt);
            static const QStringList labels = {
                "Source port","Destination port","Verification Tag","Checksum"
            };
            PacketLayer sctp6Layer;
            sctp6Layer.name = "Stream Control Transmission Protocol";
            field.category = "SCTP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                sctp6Layer.fields.append(field);
            }
            layers.append(sctp6Layer);
        }
        // --- UDP-Lite ---
        else if (ip6->ip6_nxt == IPPROTO_UDPLITE) {
            auto vals = parseUdplite(pkt);
            static const QStringList labels = {
                "Source port","Destination port","Checksum coverage","Checksum"
            };
            PacketLayer udplite6Layer;
            udplite6Layer.name = "UDP-Lite";
            field.category = "UDP-Lite Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                udplite6Layer.fields.append(field);
            }
            layers.append(udplite6Layer);
        }
        // --- GRE ---
        else if (ip6->ip6_nxt == IPPROTO_GRE) {
            auto vals = parseGre(pkt);
            static const QStringList labels = {
                "Flags","Version","Protocol"
            };
            PacketLayer gre6Layer;
            gre6Layer.name = "Generic Routing Encapsulation";
            field.category = "GRE Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                gre6Layer.fields.append(field);
            }
            layers.append(gre6Layer);
        }
        // --- RSVP ---
        else if (ip6->ip6_nxt == IPPROTO_RSVP) {
            auto vals = parseRsvp(pkt);
            static const QStringList labels = {
                "Version","Message Type","Checksum","Send TTL","Length"
            };
            PacketLayer rsvp6Layer;
            rsvp6Layer.name = "Resource Reservation Protocol";
            field.category = "RSVP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                rsvp6Layer.fields.append(field);
            }
            layers.append(rsvp6Layer);
        }
        // --- PIM ---
        else if (ip6->ip6_nxt == IPPROTO_PIM) {
            auto vals = parsePim(pkt);
            static const QStringList labels = {
                "Version","Message Type","Checksum"
            };
            PacketLayer pim6Layer;
            pim6Layer.name = "Protocol Independent Multicast";
            field.category = "PIM Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                pim6Layer.fields.append(field);
            }
            layers.append(pim6Layer);
        }
        // --- IPsec AH ---
        else if (ip6->ip6_nxt == IPPROTO_AH) {
            auto vals = parseAh(pkt);
            static const QStringList labels = {
                "Next Header","Payload Length","SPI","Sequence Number"
            };
            PacketLayer ah6Layer;
            ah6Layer.name = "Authentication Header";
            field.category = "AH Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                ah6Layer.fields.append(field);
            }
            layers.append(ah6Layer);
        }
        // --- IPsec ESP ---
        else if (ip6->ip6_nxt == IPPROTO_ESP) {
            auto vals = parseEsp(pkt);
            static const QStringList labels = {
                "SPI","Sequence Number"
            };
            PacketLayer esp6Layer;
            esp6Layer.name = "Encapsulating Security Payload";
            field.category = "ESP Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                esp6Layer.fields.append(field);
            }
            layers.append(esp6Layer);
        }
        // --- MPLS-in-IP ---
        else if (ip6->ip6_nxt == IPPROTO_MPLS) {
            auto vals = parseMpls(pkt);
            static const QStringList labels = {
                "Label","Traffic Class","Bottom of Stack","TTL"
            };
            PacketLayer mpls6Layer;
            mpls6Layer.name = "Multiprotocol Label Switching";
            field.category = "MPLS Entry";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                mpls6Layer.fields.append(field);
            }
            layers.append(mpls6Layer);
        }
        // --- IPv6 Hop-by-Hop Options ---
        else if (ip6->ip6_nxt == IPPROTO_HOPOPTS) {
            auto vals = parseIpv6HopByHop(pkt);
            static const QStringList labels = {
                "Next Header","Next Header Name","Header Length"
            };
            PacketLayer hopLayer;
            hopLayer.name = "IPv6 Hop-by-Hop Options";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                hopLayer.fields.append(field);
            }
            layers.append(hopLayer);
        }
        // --- IPv6 Routing Header ---
        else if (ip6->ip6_nxt == IPPROTO_ROUTING) {
            auto vals = parseIpv6Routing(pkt);
            static const QStringList labels = {
                "Next Header","Next Header Name","Routing Type","Segments Left"
            };
            PacketLayer routingLayer;
            routingLayer.name = "IPv6 Routing Header";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                routingLayer.fields.append(field);
            }
            layers.append(routingLayer);
        }
        // --- IPv6 Fragment Header ---
        else if (ip6->ip6_nxt == IPPROTO_FRAGMENT) {
            auto vals = parseIpv6Fragment(pkt);
            static const QStringList labels = {
                "Next Header","Next Header Name","Offset","More Fragments","Identification"
            };
            PacketLayer fragLayer;
            fragLayer.name = "IPv6 Fragment Header";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                fragLayer.fields.append(field);
            }
            layers.append(fragLayer);
        }
        // --- IPv6 Destination Options ---
        else if (ip6->ip6_nxt == IPPROTO_DSTOPTS) {
            auto vals = parseIpv6Destination(pkt);
            static const QStringList labels = {
                "Next Header","Next Header Name","Header Length"
            };
            PacketLayer destLayer;
            destLayer.name = "IPv6 Destination Options";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                destLayer.fields.append(field);
            }
            layers.append(destLayer);
        }
        // --- IPv6 Mobility Header ---
        else if (ip6->ip6_nxt == IPPROTO_MH) {
            auto vals = parseIpv6Mobility(pkt);
            static const QStringList labels = {
                "Next Header","Next Header Name","Mobility Type","Checksum"
            };
            PacketLayer mobilityLayer;
            mobilityLayer.name = "IPv6 Mobility Header";
            field.category = "Extension Header";
            for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
                field.label = labels[i];
                field.value = vals[i];
                mobilityLayer.fields.append(field);
            }
            layers.append(mobilityLayer);
        }
    }
    // --- ARP ---
    else if (et == ETHERTYPE_ARP) {
        auto vals = parseArp(pkt);
        static const QStringList labels = {
            "Sender IP","Target IP",
            "HW Type","Proto Type","HLEN","PLEN","Operation",
            "Sender MAC","Target MAC"
        };
        PacketLayer arpLayer;
        arpLayer.name = "Address Resolution Protocol";
        field.category = "ARP Header";
        for (int i = 0; i < qMin(labels.size(), vals.size()); ++i) {
            field.label = labels[i];
            field.value = vals[i];
            arpLayer.fields.append(field);
        }
        layers.append(arpLayer);
    }

    return layers;
}



void Sniffing::saveToPcap(const QString &filePath) {
    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t *dumper = pcap_dump_open(pcap, filePath.toUtf8().constData());

    timeval ts;
    ts.tv_sec = 0; ts.tv_usec = 0;

    QMutexLocker locker(&packetMutex);
    for (const QByteArray &raw : packetBuffer) {
        pcap_pkthdr hdr;
        hdr.ts = ts;
        hdr.caplen = raw.size();
        hdr.len = raw.size();
        pcap_dump((u_char*)dumper, &hdr, (const u_char*)raw.constData());
    }

    pcap_dump_close(dumper);
    pcap_close(pcap);
}

void Sniffing::openFromPcap(const QString &filePath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filePath.toUtf8().constData(), errbuf);
    if (!handle) {
        qWarning("Failed to open pcap file: %s", errbuf);
        return;
    }

    const u_char *raw;
    struct pcap_pkthdr *header;

    {
        QMutexLocker locker(&packetMutex);
        packetBuffer.clear();
    }

    while (true) {
        int res = pcap_next_ex(handle, &header, &raw);
        if (res == 1) {
            QByteArray pkt(reinterpret_cast<const char*>(raw), header->caplen);
            appendPacket(pkt);  
        }
        else if (res == -2) {
            break;
        }
        else if (res == -1) {
            qWarning("Error reading packet: %s", pcap_geterr(handle));
            break;
        }
    }

    pcap_close(handle);
}


// here are my sniffing infos
QVector<QByteArray> Sniffing::packetBuffer;
QMutex Sniffing::packetMutex;

void Sniffing::appendPacket(const QByteArray &raw) {
    QMutexLocker locker(&packetMutex);
    packetBuffer.append(raw);
}

const QVector<QByteArray>& Sniffing::getAllPackets() {
    return packetBuffer;
}

void Sniffing::clearBuffer() {
    QMutexLocker locker(&packetMutex);
    packetBuffer.clear();
}
