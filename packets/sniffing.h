#ifndef SNIFFING_H
#define SNIFFING_H

#include <QString>
#include "protocols/proto_struct.h"
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <QByteArray>
#include <QStringList>
#include <QVector>
#include <QMutex>

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

struct ProtoField {
    QString category;   // "Header", "Options", "Checksum"…
    QString label;      // f.first
    QString value;      // f.second
};

struct PacketLayer {
    QString name;
    QVector<ProtoField> fields;
};

struct CapturedPacket {
    QByteArray data;
    int linkType = DLT_EN10MB;
};

class PacketWorker;

class Sniffing {
public:
    Sniffing();
    ~Sniffing();

    static void packet_callback(u_char *args,
                                const struct pcap_pkthdr *header,
                                const u_char *packet);
    // === Parsers ====
    QStringList parseArp(const u_char *pkt, int linkType) const;
    QStringList parseTcp(const u_char *pkt, int linkType) const;
    QStringList parseUdp(const u_char *pkt, int linkType) const;
    QStringList parseIcmp(const u_char *pkt, int linkType) const;
    QStringList parseIcmpv6(const u_char *pkt, int linkType) const;
    QStringList parseIgmp(const u_char *pkt, int linkType) const;
    QStringList parseSctp(const u_char *pkt, int linkType) const;
    QStringList parseUdplite(const u_char *pkt, int linkType) const;
    QStringList parseGre(const u_char *pkt, int linkType) const;
    QStringList parseOspf(const u_char *pkt, int linkType) const;
    QStringList parseRsvp(const u_char *pkt, int linkType) const;
    QStringList parsePim(const u_char *pkt, int linkType) const;
    QStringList parseEgp(const u_char *pkt, int linkType) const;
    QStringList parseAh(const u_char *pkt, int linkType) const;
    QStringList parseEsp(const u_char *pkt, int linkType) const;
    QStringList parseMpls(const u_char *pkt, int linkType) const;
    QStringList parseIpip(const u_char *pkt, int linkType) const;
    QStringList parseIpv6HopByHop(const u_char *pkt, int linkType) const;
    QStringList parseIpv6Routing(const u_char *pkt, int linkType) const;
    QStringList parseIpv6Fragment(const u_char *pkt, int linkType) const;
    QStringList parseIpv6Destination(const u_char *pkt, int linkType) const;
    QStringList parseIpv6Mobility(const u_char *pkt, int linkType) const;
    // ================

    QVector<PacketLayer> parseLayers(const u_char* pkt, int linkType) const;

    QString toHexAscii(const u_char *payload, int len) const;
    QStringList packetSummary(const u_char *packet, int total_len, int linkType) const;

    //These are for saving and opening my pcap files
    void saveToPcap(const QString &filePath);
    void openFromPcap(const QString &filePath);

    //I will use this to save my packet sniffing session later
    static QVector<CapturedPacket> packetBuffer;
    static QMutex packetMutex;
    static void appendPacket(const CapturedPacket &packet);
    static const QVector<CapturedPacket>& getAllPackets();
    void clearBuffer();

};

#endif // SNIFFING_H
