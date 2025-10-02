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

struct ProtoField {
    QString category;   // "Header", "Options", "Checksum"…
    QString label;      // f.first
    QString value;      // f.second
};

struct PacketLayer {
    QString name;
    QVector<ProtoField> fields;
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
    QStringList parseArp(const u_char *pkt, int datalinkType = DLT_EN10MB) const;
    QStringList parseTcp(const u_char *pkt, int datalinkType = DLT_EN10MB) const;
    QStringList parseUdp(const u_char *pkt, int datalinkType = DLT_EN10MB) const;
    QStringList parseIcmp(const u_char *pkt, int datalinkType = DLT_EN10MB) const;
    // ================

    QVector<PacketLayer> parseLayers(const u_char* pkt, int datalinkType = DLT_EN10MB) const;

    QString toHexAscii(const u_char *payload, int len) const;
    QStringList packetSummary(const u_char *packet, int total_len, int datalinkType = DLT_EN10MB) const;

    //These are for saving and opening my pcap files
    void saveToPcap(const QString &filePath);
    void openFromPcap(const QString &filePath);

    //I will use this to save my packet sniffing session later
    static QVector<QByteArray> packetBuffer;
    static QVector<int> packetDatalinks;
    static QMutex packetMutex;
    static void appendPacket(const QByteArray &raw, int datalinkType = DLT_EN10MB);
    static const QVector<QByteArray>& getAllPackets();
    static const QVector<int>& getAllDatalinks();
    void clearBuffer();

};

#endif // SNIFFING_H
