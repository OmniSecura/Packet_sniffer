#include "mainwindow.h"
#include "protocols/proto_struct.h"
#include "coloring/packetcolorizer.h"
#include "theme/theme.h"
#include "gui/mainwindow_ui.h"
#include "statistics/sessionmanagerdialog.h"

#include <QComboBox>
#include <QFileInfo>
#include <QLineEdit>
#include <QTimer>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ifaceBox(nullptr),
      filterEdit(nullptr),
      promiscBox(nullptr),
      startBtn(nullptr),
      stopBtn(nullptr),
      packetTable(nullptr),
      packetModel(nullptr), //new for QTableView
      detailsTree(nullptr),
      hexEdit(nullptr),
      workerThread(nullptr),
      worker(nullptr)
{
    Theme::loadTheme();
    setupUI();

    connect(ifaceBox, &QComboBox::currentTextChanged,
            this, [this](const QString &text) {
                appSettings.setLastUsedInterface(text);
            });
    connect(promiscBox, &QCheckBox::toggled,
            this, [this](bool checked) {
                appSettings.setPromiscuousMode(checked);
            });
    connect(filterEdit, &QLineEdit::editingFinished,
            this, [this]() {
                appSettings.setDefaultFilter(filterEdit->text());
            });

    listInterfaces();
    loadPreferences();
    packetColorizer.loadRulesFromSettings();
}

MainWindow::~MainWindow() {
    packetColorizer.saveRulesToSettings();
    stopSniffing();
}

void MainWindow::loadPreferences() {
    promiscBox->setChecked(appSettings.promiscuousMode());
    filterEdit->setText(appSettings.defaultFilter());

    const QString preferredInterface = appSettings.defaultInterface();
    if (!preferredInterface.isEmpty()) {
        const int index = ifaceBox->findText(preferredInterface);
        if (index != -1) {
            ifaceBox->setCurrentIndex(index);
            return;
        }
    }

    const QString lastUsed = appSettings.lastUsedInterface();
    if (!lastUsed.isEmpty()) {
        const int index = ifaceBox->findText(lastUsed);
        if (index != -1) {
            ifaceBox->setCurrentIndex(index);
        }
    }

    themeToggleAction->setText(Theme::toggleActionText());

    if (appSettings.autoStartCapture() && startBtn->isEnabled() && ifaceBox->count() > 0) {
        QTimer::singleShot(0, startBtn, &QPushButton::click);
    }
}

void MainWindow::openSessionManager()
{
    SessionManagerDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) {
        return;
    }

    const auto record = dlg.selectedSession();
    if (!record) {
        return;
    }

    auto loaded = SessionStorage::loadSession(*record);
    if (!loaded) {
        QMessageBox::warning(this,
                             tr("Session Manager"),
                             tr("Failed to load the selected session."));
        return;
    }

    if (!loadOfflineSession(*loaded)) {
        QMessageBox::warning(this,
                             tr("Session Manager"),
                             tr("Unable to display the selected session."));
    }
}

void MainWindow::persistCurrentSession()
{
    if (!stats) {
        return;
    }

    const QString statsDir = Statistics::defaultSessionsDir();
    stats->SaveStatsToJson(statsDir);

    const QString statsFile = stats->lastFilePath();
    if (!statsFile.isEmpty()) {
        QFileInfo info(statsFile);
        const QString pcapPath = info.absolutePath()
                               + QLatin1Char('/')
                               + info.completeBaseName()
                               + QStringLiteral(".pcap");
        parser.saveToPcap(pcapPath);
    }
}

bool MainWindow::loadOfflineSession(const SessionStorage::LoadedSession &session)
{
    if (stopBtn && stopBtn->isEnabled()) {
        stopSniffing();
    }

    if (sessionTimer) {
        sessionTimer->stop();
    }

    startNewSession();
    stats.reset();
    protocolCounts.clear();

    qint64 duration = 0;
    if (session.record.startTime.isValid() && session.record.endTime.isValid()) {
        duration = session.record.startTime.secsTo(session.record.endTime);
        if (duration < 0) {
            duration = 0;
        }
    }
    sessionStartTime = QDateTime::currentDateTime().addSecs(-duration);
    updateSessionTime();

    parser.clearBuffer();

    QDateTime packetTimestamp = session.record.startTime.isValid()
        ? session.record.startTime
        : QDateTime::currentDateTime();

    for (const CapturedPacket &packet : session.packets) {
        Sniffing::appendPacket(packet);
        QStringList infos;
        infos << QString::number(packetTimestamp.toSecsSinceEpoch())
              << QString::number(packet.data.size());
        handlePacket(packet.data, infos, packet.linkType);
        packetTimestamp = packetTimestamp.addMSecs(1);
    }

    return true;
}

void MainWindow::applyFlowFilter(const QString &protocol,
                                 const QString &srcAddr,
                                 quint16 srcPort,
                                 const QString &dstAddr,
                                 quint16 dstPort)
{
    FlowFilterCriteria criteria;
    criteria.protocol = protocol;
    criteria.srcAddress = srcAddr;
    criteria.srcPort = srcPort;
    criteria.dstAddress = dstAddr;
    criteria.dstPort = dstPort;
    m_activeFlowFilter = criteria;
    refreshFlowFilter();
}

void MainWindow::clearFlowFilter()
{
    if ((!packetTable || !packetModel)) {
        m_activeFlowFilter.reset();
        return;
    }

    if (!m_activeFlowFilter.has_value()) {
        // ensure table rows are visible even if no filter was active
        for (int row = 0; row < packetModel->rowCount(); ++row)
            packetTable->setRowHidden(row, false);
        return;
    }

    m_activeFlowFilter.reset();
    for (int row = 0; row < packetModel->rowCount(); ++row)
        packetTable->setRowHidden(row, false);
}

bool MainWindow::matchesFlowFilter(const PacketTableRow &row) const
{
    if (!m_activeFlowFilter.has_value()) {
        return true;
    }

    const auto &criteria = *m_activeFlowFilter;
    return row.protocol == criteria.protocol
        && row.srcAddress == criteria.srcAddress
        && row.dstAddress == criteria.dstAddress
        && row.srcPort == criteria.srcPort
        && row.dstPort == criteria.dstPort;
}

void MainWindow::refreshFlowFilter()
{
    if (!packetTable || !packetModel)
        return;

    for (int row = 0; row < packetModel->rowCount(); ++row) {
        const PacketTableRow rowData = packetModel->row(row);
        const bool visible = matchesFlowFilter(rowData);
        packetTable->setRowHidden(row, !visible);
    }
}
