#include "statistics.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

Statistics::Statistics(const QDateTime &sessionStart)
    : m_sessionStart(sessionStart),
      m_sessionEnd(sessionStart)
{
}

Statistics::~Statistics() = default;

void Statistics::recordPacket(const QDateTime &timestamp,
                              const QString &protocol,
                              const QString &src,
                              const QString &dst,
                              quint64 packetSize)
{
    int sec = static_cast<int>(m_sessionStart.secsTo(timestamp));
    if (sec < 0) return;
    if (timestamp > m_sessionEnd) {
        m_sessionEnd = timestamp;
    }
    statsProtocolPerSecond[sec][protocol] += 1;
    statsConnectionsPerSecond[sec].insert(qMakePair(src, dst));
    statsBytesPerSecond[sec] += packetSize;
    statsPacketsPerSecond[sec] += 1;
}

void Statistics::SaveStatsToJson(const QString &dirPath)
{
    if (statsProtocolPerSecond.isEmpty()) {
        return;
    }

    QDir().mkpath(dirPath);
    QString startStr = m_sessionStart.toString(Qt::ISODate);
    QString endStr   = m_sessionEnd.toString(Qt::ISODate);
    startStr.replace(":", "-");
    endStr.replace(":", "-");
    QString filePath = QDir(dirPath).filePath(startStr + "-" + endStr + ".json");

    if (!m_lastFilePath.isEmpty() && m_lastFilePath != filePath) {
        QFile::remove(m_lastFilePath);
    }
    m_lastFilePath = filePath;

    QJsonObject sessionObj;
    sessionObj.insert("sessionStart", m_sessionStart.toString(Qt::ISODate));
    sessionObj.insert("sessionEnd",   m_sessionEnd.toString(Qt::ISODate));

    QJsonArray perSecondArray;
    QList<int> seconds = statsProtocolPerSecond.keys();
    std::sort(seconds.begin(), seconds.end());
    for (int sec : seconds) {
        QJsonObject secondObj;
        secondObj.insert("second", sec);

        QJsonObject protoCountsObj;
        for (auto it = statsProtocolPerSecond.value(sec).constBegin();
             it != statsProtocolPerSecond.value(sec).constEnd(); ++it) {
            protoCountsObj.insert(it.key(), it.value());
        }
        secondObj.insert("protocolCounts", protoCountsObj);

        QJsonArray connArray;
        for (const auto &p : statsConnectionsPerSecond.value(sec)) {
            QJsonObject c;
            c.insert("src", p.first);
            c.insert("dst", p.second);
            connArray.append(c);
        }
        secondObj.insert("connections", connArray);

        quint64 packets = statsPacketsPerSecond.value(sec, 0ULL);
        quint64 bytes   = statsBytesPerSecond.value(sec, 0ULL);
        double avgPacketSize = packets > 0
            ? static_cast<double>(bytes) / static_cast<double>(packets)
            : 0.0;
        secondObj.insert("avgPacketSize", avgPacketSize);
        secondObj.insert("pps", static_cast<double>(packets));
        secondObj.insert("bps", static_cast<double>(bytes));

        perSecondArray.append(secondObj);
    }
    sessionObj.insert("perSecond", perSecondArray);
    
    QJsonDocument newDoc(sessionObj);
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(newDoc.toJson());
        file.close();
    }
}

QString Statistics::lastFilePath() const
{
    return m_lastFilePath;
}

QString Statistics::defaultSessionsDir()
{
    return QCoreApplication::applicationDirPath() + "/src/statistics/sessions";
}
