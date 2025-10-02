#include "mainwindow.h"
#include "protocols/proto_struct.h"
#include "coloring/packetcolorizer.h"
#include "theme/theme.h"
#include "gui/mainwindow_ui.h"

#include <QComboBox>
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
                appSettings.setDefaultInterface(text);
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

    if (stats) {
        const QString statsDir = "src/statistics/sessions";
        stats->SaveStatsToJson(statsDir);
        stats.reset();
    }
}

void MainWindow::loadPreferences() {
    promiscBox->setChecked(appSettings.promiscuousMode());
    filterEdit->setText(appSettings.defaultFilter());

    const QString preferredInterface = appSettings.defaultInterface();
    if (!preferredInterface.isEmpty()) {
        const int index = ifaceBox->findText(preferredInterface);
        if (index != -1) {
            ifaceBox->setCurrentIndex(index);
        }
    }

    themeToggleAction->setText(Theme::toggleActionText());

    if (appSettings.autoStartCapture() && startBtn->isEnabled() && ifaceBox->count() > 0) {
        QTimer::singleShot(0, startBtn, &QPushButton::click);
    }
}
