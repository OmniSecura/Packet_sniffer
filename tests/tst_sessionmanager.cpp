#include <QtTest/QtTest>
#include <QApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <optional>

#include "statistics/sessionmanagerdialog.h"
#include "statistics/sessionstorage.h"
#include "packets/sniffing.h"
#include "packets/packethelpers.h"

class SessionManagerIntegrationTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void dialogListsSessions();
    void dialogLoadsSession();
    void cleanupTestCase();

private:
    QByteArray tcpPacket() const;
    QByteArray udpPacket() const;

    QString m_sessionsDir;
    QString m_jsonPath;
    QString m_pcapPath;
    QString m_startIso;
    QString m_endIso;
    QVector<QByteArray> m_expectedPackets;
};

QByteArray SessionManagerIntegrationTest::tcpPacket() const
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
    tcp.th_offx2 = (5 << 4);
    tcp.th_flags = TH_SYN;
    tcp.th_win = htons(65535);

    QByteArray pkt;
    pkt.append(reinterpret_cast<const char*>(&eth), sizeof(eth));
    pkt.append(reinterpret_cast<const char*>(&ip), sizeof(ip));
    pkt.append(reinterpret_cast<const char*>(&tcp), sizeof(tcp));
    return pkt;
}

QByteArray SessionManagerIntegrationTest::udpPacket() const
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
    ip.ip_src.s_addr = inet_addr("192.0.2.3");
    ip.ip_dst.s_addr = inet_addr("192.0.2.4");

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

void SessionManagerIntegrationTest::initTestCase()
{
    m_sessionsDir = SessionStorage::sessionsDirectory();
    QVERIFY(QDir().mkpath(m_sessionsDir));

    const auto now = QDateTime::currentDateTimeUtc();
    m_startIso = now.toString(Qt::ISODate);
    m_endIso = now.addSecs(1).toString(Qt::ISODate);

    const QString baseName = QStringLiteral("test-session-%1")
        .arg(now.toString(QStringLiteral("yyyyMMddhhmmsszzz")));
    QDir dir(m_sessionsDir);
    m_jsonPath = dir.filePath(baseName + QStringLiteral(".json"));
    m_pcapPath = dir.filePath(baseName + QStringLiteral(".pcap"));

    QJsonObject root;
    root.insert(QStringLiteral("sessionStart"), m_startIso);
    root.insert(QStringLiteral("sessionEnd"), m_endIso);

    QJsonArray perSecond;
    {
        QJsonObject entry;
        entry.insert(QStringLiteral("second"), 0);
        QJsonObject counts;
        counts.insert(QStringLiteral("TCP"), 1);
        entry.insert(QStringLiteral("protocolCounts"), counts);
        QJsonArray connections;
        connections.append(QJsonObject{{QStringLiteral("src"), QStringLiteral("192.0.2.1")},
                                       {QStringLiteral("dst"), QStringLiteral("192.0.2.2")}});
        entry.insert(QStringLiteral("connections"), connections);
        entry.insert(QStringLiteral("avgPacketSize"), 60.0);
        entry.insert(QStringLiteral("pps"), 1.0);
        entry.insert(QStringLiteral("bps"), 60.0);
        perSecond.append(entry);
    }
    {
        QJsonObject entry;
        entry.insert(QStringLiteral("second"), 1);
        QJsonObject counts;
        counts.insert(QStringLiteral("UDP"), 1);
        entry.insert(QStringLiteral("protocolCounts"), counts);
        entry.insert(QStringLiteral("connections"), QJsonArray());
        entry.insert(QStringLiteral("avgPacketSize"), 50.0);
        entry.insert(QStringLiteral("pps"), 1.0);
        entry.insert(QStringLiteral("bps"), 50.0);
        perSecond.append(entry);
    }
    root.insert(QStringLiteral("perSecond"), perSecond);

    QFile jsonFile(m_jsonPath);
    QVERIFY(jsonFile.open(QIODevice::WriteOnly | QIODevice::Truncate));
    jsonFile.write(QJsonDocument(root).toJson());
    jsonFile.close();

    m_expectedPackets = { tcpPacket(), udpPacket() };

    Sniffing sniffer;
    sniffer.clearBuffer();
    for (const auto &pkt : m_expectedPackets) {
        Sniffing::appendPacket(pkt);
    }
    sniffer.saveToPcap(m_pcapPath);
    sniffer.clearBuffer();
}

void SessionManagerIntegrationTest::dialogListsSessions()
{
    SessionManagerDialog dlg;
    const auto sessions = dlg.sessions();

    bool found = false;
    for (const auto &record : sessions) {
        if (QFileInfo(record.jsonPath) == QFileInfo(m_jsonPath)) {
            found = true;
            QVERIFY(record.hasPcap);
            QCOMPARE(record.totalPackets, 2);
            QVERIFY(record.protocols.contains(QStringLiteral("TCP")));
            QVERIFY(record.protocols.contains(QStringLiteral("UDP")));
            break;
        }
    }
    QVERIFY(found);
}

void SessionManagerIntegrationTest::dialogLoadsSession()
{
    SessionManagerDialog dlg;
    const auto sessions = dlg.sessions();

    std::optional<SessionStorage::SessionRecord> record;
    for (const auto &entry : sessions) {
        if (QFileInfo(entry.jsonPath) == QFileInfo(m_jsonPath)) {
            record = entry;
            break;
        }
    }
    QVERIFY(record.has_value());

    auto loaded = SessionStorage::loadSession(*record);
    QVERIFY(loaded.has_value());
    QCOMPARE(loaded->packets.size(), m_expectedPackets.size());
    QCOMPARE(loaded->packets.first(), m_expectedPackets.first());
    QCOMPARE(loaded->statsDocument.object().value(QStringLiteral("sessionStart")).toString(), m_startIso);
    QCOMPARE(loaded->statsDocument.object().value(QStringLiteral("sessionEnd")).toString(), m_endIso);
}

void SessionManagerIntegrationTest::cleanupTestCase()
{
    QFile::remove(m_jsonPath);
    QFile::remove(m_pcapPath);
}

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    SessionManagerIntegrationTest tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "tst_sessionmanager.moc"
