#ifndef FLOWTABLEMODEL_H
#define FLOWTABLEMODEL_H

#include <QAbstractTableModel>
#include <QDateTime>
#include <QFileSystemWatcher>
#include <QHashFunctions>
#include <QStringList>
#include <QVector>
#include <QtGlobal>

#include "charts/ChartConfig.h"

class FlowTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    enum Column {
        ProtocolColumn = 0,
        SourceColumn,
        SourcePortColumn,
        DestinationColumn,
        DestinationPortColumn,
        PacketsColumn,
        BytesColumn,
        DurationColumn,
        FirstSeenColumn,
        LastSeenColumn,
        SessionColumn,
        ColumnCount
    };

    struct FlowEntry {
        QString protocol;
        QString srcAddress;
        quint16 srcPort = 0;
        QString dstAddress;
        quint16 dstPort = 0;
        quint64 packets = 0;
        quint64 bytes = 0;
        qint64 durationSeconds = 0;
        QDateTime firstSeen;
        QDateTime lastSeen;
        QString sessionLabel;
        int sessionIndex = -1;
    };

    explicit FlowTableModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    void setMode(chart::Mode mode);
    void setSessionIndex(int index);

    QStringList availableSessionLabels() const;
    FlowEntry entryAt(int row) const;
    QVector<FlowEntry> currentEntries() const;

signals:
    void sessionsChanged();

private slots:
    void reload();

private:
    struct SessionFlows {
        QString label;
        QVector<FlowEntry> flows;
        QDateTime startTime;
        QDateTime endTime;
    };

    struct AggregationKey {
        QString protocol;
        QString srcAddress;
        QString dstAddress;
        quint16 srcPort = 0;
        quint16 dstPort = 0;

        bool operator==(const AggregationKey &other) const noexcept
        {
            return protocol == other.protocol
                && srcAddress == other.srcAddress
                && dstAddress == other.dstAddress
                && srcPort == other.srcPort
                && dstPort == other.dstPort;
        }
    };

    friend uint qHash(const AggregationKey &key, uint seed) noexcept;

    QFileSystemWatcher m_watcher;
    QString m_sessionsDir;
    QVector<SessionFlows> m_sessions;
    QVector<FlowEntry> m_displayRows;
    chart::Mode m_mode = chart::Mode::AllTime;
    int m_sessionIndex = -1;

    void rebuildDisplay();
};

inline uint qHash(const FlowTableModel::AggregationKey &key, uint seed = 0) noexcept
{
    return qHashMulti(seed, key.protocol, key.srcAddress, key.dstAddress,
                      key.srcPort, key.dstPort);
}

#endif // FLOWTABLEMODEL_H
