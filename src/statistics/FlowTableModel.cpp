#include "FlowTableModel.h"
#include "statistics.h"

#include <algorithm>
#include <QDir>
#include <QFile>
#include <QIODevice>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTime>

FlowTableModel::FlowTableModel(QObject *parent)
    : QAbstractTableModel(parent)
{
    m_sessionsDir = Statistics::defaultSessionsDir();
    if (!m_sessionsDir.isEmpty()) {
        QDir().mkpath(m_sessionsDir);
        if (!m_sessionsDir.isEmpty()) {
            m_watcher.addPath(m_sessionsDir);
            connect(&m_watcher, &QFileSystemWatcher::directoryChanged,
                    this, &FlowTableModel::reload);
        }
    }
    reload();
}

int FlowTableModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return m_displayRows.size();
}

int FlowTableModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return ColumnCount;
}

QVariant FlowTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_displayRows.size()) {
        return {};
    }

    const FlowEntry &entry = m_displayRows.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case ProtocolColumn:
            return entry.protocol;
        case SourceColumn:
            return entry.srcAddress;
        case SourcePortColumn:
            return entry.srcPort == 0 ? QStringLiteral("-") : QString::number(entry.srcPort);
        case DestinationColumn:
            return entry.dstAddress;
        case DestinationPortColumn:
            return entry.dstPort == 0 ? QStringLiteral("-") : QString::number(entry.dstPort);
        case PacketsColumn:
            return QVariant::fromValue<qulonglong>(entry.packets);
        case BytesColumn:
            return QVariant::fromValue<qulonglong>(entry.bytes);
        case DurationColumn:
            return entry.durationSeconds >= 0
                    ? QStringLiteral("%1 s").arg(entry.durationSeconds)
                    : QStringLiteral("-");
        case FirstSeenColumn:
            return entry.firstSeen.isValid()
                    ? entry.firstSeen.toString(Qt::ISODate)
                    : QStringLiteral("-");
        case LastSeenColumn:
            return entry.lastSeen.isValid()
                    ? entry.lastSeen.toString(Qt::ISODate)
                    : QStringLiteral("-");
        case SessionColumn:
            return entry.sessionLabel;
        default:
            break;
        }
    }

    return {};
}

QVariant FlowTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        switch (section) {
        case ProtocolColumn:       return tr("Protocol");
        case SourceColumn:         return tr("Source");
        case SourcePortColumn:     return tr("Src Port");
        case DestinationColumn:    return tr("Destination");
        case DestinationPortColumn:return tr("Dst Port");
        case PacketsColumn:        return tr("Packets");
        case BytesColumn:          return tr("Bytes");
        case DurationColumn:       return tr("Duration");
        case FirstSeenColumn:      return tr("First Seen");
        case LastSeenColumn:       return tr("Last Seen");
        case SessionColumn:        return tr("Session");
        default:                   break;
        }
    }
    return QAbstractTableModel::headerData(section, orientation, role);
}

void FlowTableModel::setMode(chart::Mode mode)
{
    if (m_mode == mode) {
        return;
    }
    m_mode = mode;
    beginResetModel();
    rebuildDisplay();
    endResetModel();
}

void FlowTableModel::setSessionIndex(int index)
{
    if (m_sessionIndex == index && m_mode == chart::Mode::BySession) {
        return;
    }
    m_sessionIndex = index;
    m_mode = chart::Mode::BySession;
    beginResetModel();
    rebuildDisplay();
    endResetModel();
}

QStringList FlowTableModel::availableSessionLabels() const
{
    QStringList labels;
    labels.reserve(m_sessions.size());
    for (const SessionFlows &session : m_sessions) {
        labels.append(session.label);
    }
    return labels;
}

FlowTableModel::FlowEntry FlowTableModel::entryAt(int row) const
{
    return m_displayRows.value(row);
}

QVector<FlowTableModel::FlowEntry> FlowTableModel::currentEntries() const
{
    return m_displayRows;
}

void FlowTableModel::reload()
{
    beginResetModel();
    m_sessions.clear();
    m_displayRows.clear();

    QDir dir(m_sessionsDir);
    const QStringList files = dir.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Name);
    QVector<SessionFlows> sessions;
    sessions.reserve(files.size());

    for (const QString &fileName : files) {
        QFile file(dir.filePath(fileName));
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }
        const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        if (!doc.isObject()) {
            continue;
        }
        const QJsonObject obj = doc.object();
        SessionFlows session;
        session.startTime = QDateTime::fromString(obj.value(QStringLiteral("sessionStart")).toString(), Qt::ISODate);
        session.endTime = QDateTime::fromString(obj.value(QStringLiteral("sessionEnd")).toString(), Qt::ISODate);
        if (session.startTime.isValid() && session.endTime.isValid()) {
            session.label = tr("%1 → %2").arg(session.startTime.toString(Qt::ISODate),
                                               session.endTime.toString(Qt::ISODate));
        } else {
            session.label = fileName;
        }

        const QJsonArray flowsArray = obj.value(QStringLiteral("flows")).toArray();
        session.flows.reserve(flowsArray.size());
        for (const QJsonValue &value : flowsArray) {
            const QJsonObject flowObj = value.toObject();
            FlowEntry entry;
            entry.protocol = flowObj.value(QStringLiteral("protocol")).toString();
            entry.srcAddress = flowObj.value(QStringLiteral("srcAddress")).toString();
            entry.srcPort = static_cast<quint16>(flowObj.value(QStringLiteral("srcPort")).toInt());
            entry.dstAddress = flowObj.value(QStringLiteral("dstAddress")).toString();
            entry.dstPort = static_cast<quint16>(flowObj.value(QStringLiteral("dstPort")).toInt());
            entry.packets = static_cast<quint64>(flowObj.value(QStringLiteral("packets")).toDouble());
            entry.bytes = static_cast<quint64>(flowObj.value(QStringLiteral("bytes")).toDouble());
            entry.durationSeconds = static_cast<qint64>(flowObj.value(QStringLiteral("durationSeconds")).toDouble());
            entry.firstSeen = QDateTime::fromString(flowObj.value(QStringLiteral("firstSeen")).toString(), Qt::ISODate);
            entry.lastSeen = QDateTime::fromString(flowObj.value(QStringLiteral("lastSeen")).toString(), Qt::ISODate);
            session.flows.append(entry);
        }
        sessions.append(session);
    }

    std::sort(sessions.begin(), sessions.end(), [](const SessionFlows &a, const SessionFlows &b) {
        return a.startTime < b.startTime;
    });

    for (int i = 0; i < sessions.size(); ++i) {
        for (FlowEntry &entry : sessions[i].flows) {
            entry.sessionIndex = i;
            entry.sessionLabel = sessions[i].label;
        }
    }

    m_sessions = sessions;
    rebuildDisplay();
    endResetModel();
    emit sessionsChanged();
}

void FlowTableModel::rebuildDisplay()
{
    QVector<FlowEntry> rows;

    auto appendSessionFlows = [&](const SessionFlows &session) {
        for (const FlowEntry &entry : session.flows) {
            rows.append(entry);
        }
    };

    if (m_mode == chart::Mode::AllTime) {
        QHash<AggregationKey, FlowEntry> aggregated;
        for (const SessionFlows &session : m_sessions) {
            for (const FlowEntry &entry : session.flows) {
                AggregationKey key{entry.protocol, entry.srcAddress, entry.dstAddress,
                                   entry.srcPort, entry.dstPort};
                FlowEntry &agg = aggregated[key];
                if (agg.protocol.isEmpty()) {
                    agg = entry;
                    agg.sessionIndex = -1;
                } else {
                    agg.packets += entry.packets;
                    agg.bytes += entry.bytes;
                    if (!agg.firstSeen.isValid() || (entry.firstSeen.isValid() && entry.firstSeen < agg.firstSeen)) {
                        agg.firstSeen = entry.firstSeen;
                    }
                    if (!agg.lastSeen.isValid() || (entry.lastSeen.isValid() && entry.lastSeen > agg.lastSeen)) {
                        agg.lastSeen = entry.lastSeen;
                    }
                    agg.durationSeconds = qMax<qint64>(agg.durationSeconds, entry.durationSeconds);
                    if (agg.sessionLabel != entry.sessionLabel) {
                        agg.sessionLabel = tr("Multiple sessions");
                    }
                    agg.sessionIndex = -1;
                }
            }
        }
        rows = aggregated.values().toVector();
        for (FlowEntry &entry : rows) {
            if (entry.firstSeen.isValid() && entry.lastSeen.isValid()) {
                entry.durationSeconds = qMax<qint64>(0, entry.firstSeen.secsTo(entry.lastSeen));
            }
        }
    } else if (m_mode == chart::Mode::CurrentSession) {
        if (!m_sessions.isEmpty()) {
            appendSessionFlows(m_sessions.constLast());
        }
    } else if (m_mode == chart::Mode::BySession) {
        if (m_sessionIndex >= 0 && m_sessionIndex < m_sessions.size()) {
            appendSessionFlows(m_sessions.at(m_sessionIndex));
        }
    }

    std::sort(rows.begin(), rows.end(), [](const FlowEntry &a, const FlowEntry &b) {
        if (a.packets == b.packets) {
            return a.bytes > b.bytes;
        }
        return a.packets > b.packets;
    });

    m_displayRows = rows;
}
