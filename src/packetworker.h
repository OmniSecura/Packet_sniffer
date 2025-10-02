#ifndef PACKETWORKER_H
#define PACKETWORKER_H

#include <QObject>
#include <QString>
#include <QThread>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <atomic>
#include <string>
#include <QDebug>
#include <memory>
#include <pcap.h>

class PacketWorker : public QObject {
    Q_OBJECT

public:
    PacketWorker(const QString &iface,
                 const QString &filter,
                 bool promisc);
    ~PacketWorker();
    void getPacketInfo(const std::string& infos) {
        qDebug() << QString::fromStdString(infos);
    }

    
public slots:
    void process();  // capture loop
    void stop();     // signal to exit
    void updateFilter(const QString &filter); // change filter at runtime

signals:
    // rawData: packet bytes
    // infos:   [0]=timestamp, [1]=caplen, [2]=srcPort, [3]=dstPort
    void newPacket(const QByteArray &rawData,
                   QStringList infos,
                   int datalinkType);

    int datalinkType() const { return m_datalinkType; }

private:
    QString           m_iface;
    QString           m_filter;
    bool              m_promisc;
    std::atomic<bool> m_running;
    std::unique_ptr<pcap_t, decltype(&pcap_close)> m_handle{nullptr, &pcap_close};
    bpf_u_int32       m_netmask = 0;
    int               m_datalinkType = DLT_EN10MB;
};

#endif // PACKETWORKER_H
