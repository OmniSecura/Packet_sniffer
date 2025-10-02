#include "sniffing.h"
#include "packethelpers.h"
#include "src/packetworker.h"
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

    Sniffing::appendPacket(raw, worker->datalinkType());

    QStringList infos;
    infos << QString::number(header->ts.tv_sec)
          << QString::number(header->caplen);

    emit worker->newPacket(raw, infos, worker->datalinkType());
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
                                    int total_len,
                                    int datalinkType) const
{
    uint16_t ethertype = linkProtocol(packet, datalinkType);
    QString src   = "-",
            dst   = "-",
            proto = "OTHER";

    if (ethertype == ETHERTYPE_IP) {
        auto ip  = ipv4Hdr(packet, datalinkType);

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
      auto arpData = parseArp(packet, datalinkType);
      return { arpData[0], arpData[1], "ARP", QString::number(total_len) };
    }
    else if (ethertype == ETHERTYPE_IPV6) {
        auto ip6 = ipv6Hdr(packet, datalinkType);

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

QStringList Sniffing::parseArp(const u_char *pkt, int datalinkType) const {
    auto arp = arpHdr(pkt, datalinkType);

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

QStringList Sniffing::parseTcp(const u_char *pkt, int datalinkType) const {
    uint16_t ethertype = linkProtocol(pkt, datalinkType);

    const sniff_tcp *tcp = nullptr;
    char buf6[INET6_ADDRSTRLEN];
    char buf[INET_ADDRSTRLEN];

    QString src, dst;
    if (ethertype == ETHERTYPE_IP){
        auto ip = ipv4Hdr(pkt, datalinkType);
        tcp = tcpHdr(pkt, datalinkType);
        inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf));
            src = QString::fromLatin1(buf);
        inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf));
            dst = QString::fromLatin1(buf);
    }
    else if (ethertype == ETHERTYPE_IPV6) {
        auto ip6 = ipv6Hdr(pkt, datalinkType);
        tcp = tcp6Hdr(pkt, datalinkType);
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

QStringList Sniffing::parseUdp(const u_char *pkt, int datalinkType) const {
    uint16_t ethertype = linkProtocol(pkt, datalinkType);

    const sniff_udp *udp = nullptr;
    char buf[INET_ADDRSTRLEN];
    char buf6[INET6_ADDRSTRLEN];
    QString src, dst;
    if (ethertype == ETHERTYPE_IP){
        auto ip = ipv4Hdr(pkt, datalinkType);
        udp = udpHdr(pkt, datalinkType);
        if (inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf)))
            src = QString::fromLatin1(buf);
        if (inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf)))
            dst = QString::fromLatin1(buf);
    }
    else if (ethertype == ETHERTYPE_IPV6){
        auto ip6 = ipv6Hdr(pkt, datalinkType);
        udp = udp6Hdr(pkt, datalinkType);
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

QStringList Sniffing::parseIcmp(const u_char *pkt, int datalinkType) const {
    auto icmp = icmpHdr(pkt, datalinkType);
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


QVector<PacketLayer> Sniffing::parseLayers(const u_char* pkt, int datalinkType) const {
    QVector<PacketLayer> layers;
    ProtoField field;

    // --- Link Layer ---
    if (datalinkType == DLT_EN10MB) {
        if (const auto eth = ethHdr(pkt, datalinkType)) {
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
        }
    }
    else if (datalinkType == DLT_LINUX_SLL) {
        const auto sll = sllHdr(pkt);
        PacketLayer sllLayer;
        sllLayer.name = "Linux Cooked Capture";

        field.category = "Link Header";
        field.label = "Packet Type";
        field.value = QString::number(ntohs(sll->packet_type));
        sllLayer.fields.append(field);

        field.label = "ARPHRD";
        field.value = QString::number(ntohs(sll->arphrd_type));
        sllLayer.fields.append(field);

        field.label = "Address";
        field.value = macToStr(sll->link_addr, qMin<int>(ntohs(sll->link_addr_len), 8));
        sllLayer.fields.append(field);

        field.label = "Protocol";
        field.value = QString("0x%1")
                      .arg(ntohs(sll->protocol), 4, 16, QChar('0'));
        sllLayer.fields.append(field);

        layers.append(sllLayer);
    }
    else if (datalinkType == DLT_LINUX_SLL2) {
        const auto sll = sll2Hdr(pkt);
        PacketLayer sllLayer;
        sllLayer.name = "Linux Cooked Capture v2";

        field.category = "Link Header";
        field.label = "Interface Index";
        field.value = QString::number(ntohl(sll->if_index));
        sllLayer.fields.append(field);

        field.label = "ARPHRD";
        field.value = QString::number(ntohs(sll->arphrd_type));
        sllLayer.fields.append(field);

        field.label = "Packet Type";
        field.value = QString::number(sll->packet_type);
        sllLayer.fields.append(field);

        field.label = "Address";
        field.value = macToStr(sll->link_addr, qMin<int>(sll->link_addr_len, 8));
        sllLayer.fields.append(field);

        field.label = "Protocol";
        field.value = QString("0x%1")
                      .arg(ntohs(sll->protocol), 4, 16, QChar('0'));
        sllLayer.fields.append(field);

        layers.append(sllLayer);
    }

    uint16_t et = linkProtocol(pkt, datalinkType);

    // --- IPv4 ---
    if (et == ETHERTYPE_IP) {
        const auto ip = ipv4Hdr(pkt, datalinkType);
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
            auto vals = parseTcp(pkt, datalinkType);
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
            auto vals = parseUdp(pkt, datalinkType);
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
            auto vals = parseIcmp(pkt, datalinkType);
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
    }
    // --- IPv6 ---
    else if (et == ETHERTYPE_IPV6) {
        const auto ip6 = ipv6Hdr(pkt, datalinkType);
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
            auto vals = parseTcp(pkt, datalinkType);
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
            auto vals = parseUdp(pkt, datalinkType);
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
    }
    // --- ARP ---
    else if (et == ETHERTYPE_ARP) {
        auto vals = parseArp(pkt, datalinkType);
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
    int dlt = DLT_EN10MB;
    {
        QMutexLocker locker(&packetMutex);
        if (!packetDatalinks.isEmpty())
            dlt = packetDatalinks.first();
    }

    pcap_t *pcap = pcap_open_dead(dlt, 65535);
    pcap_dumper_t *dumper = pcap_dump_open(pcap, filePath.toUtf8().constData());

    timeval ts;
    ts.tv_sec = 0; ts.tv_usec = 0;

    QMutexLocker locker(&packetMutex);
    for (int i = 0; i < packetBuffer.size(); ++i) {
        const QByteArray &raw = packetBuffer.at(i);
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
    int fileDlt = pcap_datalink(handle);

    {
        QMutexLocker locker(&packetMutex);
        packetBuffer.clear();
        packetDatalinks.clear();
    }

    while (true) {
        int res = pcap_next_ex(handle, &header, &raw);
        if (res == 1) {
            QByteArray pkt(reinterpret_cast<const char*>(raw), header->caplen);
            appendPacket(pkt, fileDlt);
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
QVector<int> Sniffing::packetDatalinks;
QMutex Sniffing::packetMutex;

void Sniffing::appendPacket(const QByteArray &raw, int datalinkType) {
    QMutexLocker locker(&packetMutex);
    packetBuffer.append(raw);
    packetDatalinks.append(datalinkType);
}

const QVector<QByteArray>& Sniffing::getAllPackets() {
    return packetBuffer;
}

const QVector<int>& Sniffing::getAllDatalinks() {
    return packetDatalinks;
}

void Sniffing::clearBuffer() {
    QMutexLocker locker(&packetMutex);
    packetBuffer.clear();
    packetDatalinks.clear();
}
