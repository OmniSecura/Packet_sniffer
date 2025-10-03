#ifndef STATISTICS_H
#define STATISTICS_H

#include "charts/ChartConfig.h"
#include <QDateTime>
#include <QHash>
#include <QHashFunctions>
#include <QMap>
#include <QPair>
#include <QSet>
#include <QString>
#include <QtGlobal>
class Statistics {
public:
    explicit Statistics(const QDateTime &sessionStart);
    ~Statistics();

    void recordPacket(const QDateTime &timestamp,
                      const QString &protocol,
                      const QString &src,
                      quint16 srcPort,
                      const QString &dst,
                      quint16 dstPort,
                      quint64 packetSize);

    void SaveStatsToJson(const QString &dirPath);
    QString lastFilePath() const;

    static QString defaultSessionsDir();

private:
    QDateTime m_sessionStart;
    QDateTime m_sessionEnd;
    QMap<int, QMap<QString,int>> statsProtocolPerSecond;
    QMap<int, QSet<QPair<QString,QString>>> statsConnectionsPerSecond;
    QMap<int, quint64> statsBytesPerSecond;
    QMap<int, quint64> statsPacketsPerSecond;
    QString m_lastFilePath;

    struct FlowKey {
        QString protocol;
        QString srcAddress;
        QString dstAddress;
        quint16 srcPort = 0;
        quint16 dstPort = 0;

        bool operator==(const FlowKey &other) const noexcept {
            return protocol == other.protocol
                && srcAddress == other.srcAddress
                && dstAddress == other.dstAddress
                && srcPort == other.srcPort
                && dstPort == other.dstPort;
        }
    };

    struct FlowStats {
        quint64 packets = 0;
        quint64 bytes = 0;
        QDateTime firstSeen;
        QDateTime lastSeen;
    };

    QHash<FlowKey, FlowStats> m_flowStats;

    friend uint qHash(const FlowKey &key, uint seed) noexcept;
};

inline uint qHash(const Statistics::FlowKey &key, uint seed = 0) noexcept
{
    return qHashMulti(seed, key.protocol, key.srcAddress, key.dstAddress,
                      key.srcPort, key.dstPort);
}

#endif // STATISTICS_H
