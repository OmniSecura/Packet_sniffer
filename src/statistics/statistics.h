#ifndef STATISTICS_H
#define STATISTICS_H

#include "charts/ChartConfig.h"
class Statistics {
public:
    explicit Statistics(const QDateTime &sessionStart);
    ~Statistics();

    void recordPacket(const QDateTime &timestamp,
                      const QString &protocol,
                      const QString &src,
                      const QString &dst,
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
};

#endif // STATISTICS_H
