#include <QtTest/QtTest>
#include "packets/sniffing.h"
#include "packets/packethelpers.h"
#include "tst_sniffing.h"

// PacketWorker normally relies on Qt's meta-object system for its signal
// implementation. The unit tests only need Sniffing's parsing helpers, so we
// provide a stub to satisfy the linker when Sniffing::packet_callback is
// compiled into the test binary.
void PacketWorker::newPacket(const QByteArray &, QStringList) {}


static QByteArray tcpIpv4Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xAA\xBB", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_tcp));
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_src.s_addr = inet_addr("192.0.2.1");
    ip.ip_dst.s_addr = inet_addr("192.0.2.2");

    sniff_tcp tcp{};
    tcp.th_sport = htons(1234);
    tcp.th_dport = htons(80);
    tcp.th_seq = htonl(1);
    tcp.th_ack = htonl(0);
    tcp.th_offx2 = (5 << 4);
    tcp.th_flags = TH_SYN;
    tcp.th_win = htons(65535);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&tcp), sizeof(tcp));
    return pkt;
}

static QByteArray tcpIpv4PacketSll()
{
    sniff_linux_sll sll{};
    sll.packet_type = htons(0);
    sll.arphrd_type = htons(1);
    sll.link_addr_len = htons(6);
    memcpy(sll.link_addr, "\x66\x77\x88\x99\xAA\xBB", 6);
    sll.protocol = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_tcp));
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_src.s_addr = inet_addr("192.0.2.1");
    ip.ip_dst.s_addr = inet_addr("192.0.2.2");

    sniff_tcp tcp{};
    tcp.th_sport = htons(1234);
    tcp.th_dport = htons(80);
    tcp.th_seq = htonl(1);
    tcp.th_ack = htonl(0);
    tcp.th_offx2 = (5 << 4);
    tcp.th_flags = TH_SYN;
    tcp.th_win = htons(65535);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&sll), sizeof(sll));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&tcp), sizeof(tcp));
    return pkt;
}

static QByteArray udpIpv4Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xAA\xBB", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_udp));
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_UDP;
    ip.ip_src.s_addr = inet_addr("192.0.2.1");
    ip.ip_dst.s_addr = inet_addr("192.0.2.2");

    sniff_udp udp{};
    udp.uh_sport = htons(1111);
    udp.uh_dport = htons(2222);
    udp.uh_len = htons(sizeof(sniff_udp));

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&udp), sizeof(udp));
    return pkt;
}

static QByteArray icmpIpv4Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xAA\xBB", 6);
    eth.ether_type = htons(ETHERTYPE_IP);

    sniff_ip ip{};
    ip.ip_vhl = (4 << 4) | 5;
    ip.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_icmp));
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_ICMP;
    ip.ip_src.s_addr = inet_addr("192.0.2.1");
    ip.ip_dst.s_addr = inet_addr("192.0.2.2");

    sniff_icmp icmp{};
    icmp.icmp_type = 8;
    icmp.icmp_code = 0;

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&icmp), sizeof(icmp));
    return pkt;
}

static QByteArray tcpIpv6Packet()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\x00\x11\x22\x33\x44\x55", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xAA\xBB", 6);
    eth.ether_type = htons(ETHERTYPE_IPV6);

    sniff_ipv6 ip6{};
    ip6.ip6_flow = htonl(6 << 28);
    ip6.ip6_plen = htons(sizeof(sniff_tcp));
    ip6.ip6_nxt = IPPROTO_TCP;
    ip6.ip6_hlim = 64;
    inet_pton(AF_INET6, "2001:db8::1", &ip6.ip6_src);
    inet_pton(AF_INET6, "2001:db8::2", &ip6.ip6_dst);

    sniff_tcp tcp{};
    tcp.th_sport = htons(1234);
    tcp.th_dport = htons(80);
    tcp.th_seq = htonl(1);
    tcp.th_ack = htonl(0);
    tcp.th_offx2 = (5 << 4);
    tcp.th_flags = TH_SYN;
    tcp.th_win = htons(65535);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip6), sizeof(ip6));
    pkt.append(reinterpret_cast<const char*>(&tcp), sizeof(tcp));
    return pkt;
}

static QByteArray arpPacket()
{
    sniff_ethernet eth{};
    memcpy(eth.ether_dhost, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(eth.ether_shost, "\x66\x77\x88\x99\xaa\xbb", 6);
    eth.ether_type = htons(ETHERTYPE_ARP);

    sniff_arp arp{};
    arp.ar_hrd = htons(1);
    arp.ar_pro = htons(0x0800);
    arp.ar_hln = 6;
    arp.ar_pln = 4;
    arp.ar_op = htons(1);
    memcpy(arp.ar_sha, "\x66\x77\x88\x99\xaa\xbb", 6);
    inet_pton(AF_INET, "192.0.2.1", arp.ar_sip);
    memset(arp.ar_tha, 0, 6);
    inet_pton(AF_INET, "192.0.2.2", arp.ar_tip);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&arp), sizeof(arp));
    return pkt;
}

void SniffingTest::parseTcpIpv4()
{
    Sniffing s;
    auto pkt = tcpIpv4Packet();
    auto vals = s.parseTcp(reinterpret_cast<const u_char*>(pkt.constData()));
    QCOMPARE(vals.at(0), QString("192.0.2.1"));
    QCOMPARE(vals.at(1), QString("192.0.2.2"));
    QCOMPARE(vals.at(2), QString("1234"));
    QCOMPARE(vals.at(3), QString("80"));
}

void SniffingTest::parseUdpIpv4()
{
    Sniffing s;
    auto pkt = udpIpv4Packet();
    auto vals = s.parseUdp(reinterpret_cast<const u_char*>(pkt.constData()));
    QCOMPARE(vals.at(0), QString("192.0.2.1"));
    QCOMPARE(vals.at(1), QString("192.0.2.2"));
    QCOMPARE(vals.at(2), QString("1111"));
    QCOMPARE(vals.at(3), QString("2222"));
}

void SniffingTest::parseIcmpIpv4()
{
    Sniffing s;
    auto pkt = icmpIpv4Packet();
    auto vals = s.parseIcmp(reinterpret_cast<const u_char*>(pkt.constData()));
    QCOMPARE(vals.at(0), QString("8"));
    QCOMPARE(vals.at(1), QString("0"));
}

void SniffingTest::parseTcpIpv6()
{
    Sniffing s;
    auto pkt = tcpIpv6Packet();
    auto vals = s.parseTcp(reinterpret_cast<const u_char*>(pkt.constData()));
    QCOMPARE(vals.at(0), QString("2001:db8::1"));
    QCOMPARE(vals.at(1), QString("2001:db8::2"));
}

void SniffingTest::parseTcpLinuxSll()
{
    Sniffing s;
    auto pkt = tcpIpv4PacketSll();
    auto vals = s.parseTcp(reinterpret_cast<const u_char*>(pkt.constData()), DLT_LINUX_SLL);
    QCOMPARE(vals.at(0), QString("192.0.2.1"));
    QCOMPARE(vals.at(1), QString("192.0.2.2"));
}

void SniffingTest::parseArp()
{
    Sniffing s;
    auto pkt = arpPacket();
    auto vals = s.parseArp(reinterpret_cast<const u_char*>(pkt.constData()));
    QCOMPARE(vals.at(0), QString("192.0.2.1"));
    QCOMPARE(vals.at(1), QString("192.0.2.2"));
    QCOMPARE(vals.at(6), QString("Request"));
}

QTEST_MAIN(SniffingTest)