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
