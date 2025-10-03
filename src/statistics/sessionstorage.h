#ifndef SESSIONSTORAGE_H
#define SESSIONSTORAGE_H

#include <QDateTime>
#include <QJsonDocument>
#include <QVector>
#include <QString>
#include <QStringList>
#include <optional>
#include <QtGlobal>

#include "../../packets/sniffing.h"

namespace SessionStorage {

struct FlowRecord {
    QString protocol;
    QString srcAddress;
    quint16 srcPort = 0;
    QString dstAddress;
    quint16 dstPort = 0;
    quint64 packets = 0;
    quint64 bytes = 0;
    QDateTime firstSeen;
    QDateTime lastSeen;
    qint64 durationSeconds = 0;
};

struct SessionRecord {
    QString displayName;
    QString jsonPath;
    QString pcapPath;
    QDateTime startTime;
    QDateTime endTime;
    int totalPackets = 0;
    qint64 totalBytes = 0;
    QStringList protocols;
    bool hasPcap = false;
    QVector<FlowRecord> flows;
};

struct LoadedSession {
    SessionRecord record;
    QJsonDocument statsDocument;
    QVector<CapturedPacket> packets;
    QVector<FlowRecord> flows;
};

QString sessionsDirectory();
QVector<SessionRecord> listSessions();
std::optional<LoadedSession> loadSession(const SessionRecord &record);

} // namespace SessionStorage

#endif // SESSIONSTORAGE_H
