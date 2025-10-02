#include "mainwindow.h"
#include "protocols/proto_struct.h"
#include "coloring/packetcolorizer.h"
#include "theme/theme.h"
#include "gui/mainwindow_ui.h"

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
    listInterfaces();
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