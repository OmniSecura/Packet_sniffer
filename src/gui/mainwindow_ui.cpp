#include "mainwindow_ui.h"
#include "../theme/theme.h"
#include "../coloring/customizerdialog.h"
#include "../PacketTableModel.h"
#include "../statistics/geooverviewdialog.h"
#include "preferencesdialog.h"
#include <QSignalBlocker>
#include <QTimer>
#include <QMenu>
#include <QMenuBar>
#include <QCoreApplication>

void MainWindow::setupUI() {
    // === Central UI ===
    QWidget *central = new QWidget(this);
    auto *mainLayout = new QVBoxLayout;

    // Top bar
    auto *topBar = new QHBoxLayout;
    ifaceBox   = new QComboBox;
    filterEdit = new QLineEdit; filterEdit->setPlaceholderText("tcp port 80");
    promiscBox = new QCheckBox("Promiscuous"); promiscBox->setChecked(true);
    startBtn   = new QPushButton("Start");
    stopBtn    = new QPushButton("Stop"); stopBtn->setEnabled(false);

    topBar->addWidget(ifaceBox);
    topBar->addWidget(filterEdit);
    topBar->addWidget(promiscBox);
    topBar->addWidget(startBtn);
    topBar->addWidget(stopBtn);
    mainLayout->addLayout(topBar);

    // Packet table + details/hex splitter
    auto *mainSplitter = new QSplitter(Qt::Horizontal);

    // 1) Left Pane: Packets
    //PacketTable usage (TODO: swap QTableWidget to QTableView)
    auto *leftSplitter = new QSplitter(Qt::Vertical);
    // packetTable = new QTableWidget;
    // packetTable->setColumnCount(7);
    // packetTable->setHorizontalHeaderLabels(
    //     {"No.","Time","Source","Destination","Protocol","Length","Info"}); //QTableWidget before QTableView
    packetTable = new QTableView;
    packetModel = new PacketTableModel(this);
    packetTable->setModel(packetModel);
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    // connect(packetTable, &QTableWidget::cellClicked,
    //         this, &MainWindow::onPacketClicked); //QTableWidget before QTableView
    connect(packetTable, &QTableView::clicked,
            this, &MainWindow::onPacketClicked);
    packetTable->setContextMenuPolicy(Qt::CustomContextMenu);
    // connect(packetTable, &QTableWidget::customContextMenuRequested,
    //     this, &MainWindow::onPacketTableContextMenu); //QTableWidget before QTableView
    connect(packetTable, &QWidget::customContextMenuRequested,
            this, &MainWindow::onPacketTableContextMenu);
    leftSplitter->addWidget(packetTable);

    // Map
    const QString mapPath = QCoreApplication::applicationDirPath() + "/resources/WorldMap.svg";
    mapWidget = new GeoMapWidget(mapPath, this);
    mapWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    leftSplitter->addWidget(mapWidget); 

    mainSplitter->addWidget(leftSplitter);

    // 2) Right pane
    auto *rightSplitter = new QSplitter(Qt::Vertical);

    // 2a) Information tree
    detailsTree = new QTreeWidget;
    detailsTree->setHeaderLabels({ "Info", "Value" });
    detailsTree->setRootIsDecorated(true);
    detailsTree->setIndentation(20);
    detailsTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    detailsTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    rightSplitter->addWidget(detailsTree);

    // 2b) Hex view
    hexEdit = new QTextEdit;
    hexEdit->setReadOnly(true);
    rightSplitter->addWidget(hexEdit);

    // TOP5 Pie Chart
    pieChart = new PieChart;
    pieChart->setMinimumHeight(120);
    pieChart->setColorizer(&packetColorizer);
    rightSplitter->addWidget(pieChart);

    mainSplitter->addWidget(rightSplitter);

    mainSplitter->setStretchFactor(0, 2.5); //left
    mainSplitter->setStretchFactor(1, 1.5); //right
    leftSplitter->setStretchFactor(0, 1); // packets
    leftSplitter->setStretchFactor(1, 4); // map
    rightSplitter->setStretchFactor(0, 3); // detailsTree
    rightSplitter->setStretchFactor(1, 2); // hexEdit
    rightSplitter->setStretchFactor(2, 1); // pieChart


    mainLayout->addWidget(mainSplitter);
    central->setLayout(mainLayout);
    setCentralWidget(central);

    connect(startBtn, &QPushButton::clicked,
            this, &MainWindow::startSniffing);
    connect(stopBtn,  &QPushButton::clicked,
            this, &MainWindow::stopSniffing);
    connect(filterEdit, &QLineEdit::textChanged,
            this, &MainWindow::onFilterTextChanged);

    // === Menu bar ===
    QMenuBar *menuBar = new QMenuBar(this);
    setMenuBar(menuBar);

    auto *fileMenu = menuBar->addMenu("File");
    // === Save/Open file ===
    actionOpen = fileMenu->addAction("Open...", this, [this]() {
        QString fileName = QFileDialog::getOpenFileName(this, "Open PCAP", "", "PCAP Files (*.pcap)");
        if (!fileName.isEmpty()) {
            parser.openFromPcap(fileName);

            for (const QByteArray &raw : parser.getAllPackets()) {
                QStringList infos;
                infos << QString::number(0) << QString::number(raw.size()); 
                handlePacket(raw, infos);
            }
        }
    });

    actionSave = fileMenu->addAction("Save As...", this, [this](){
        QString fileName = QFileDialog::getSaveFileName(this, "Save PCAP", "", "PCAP Files (*.pcap)");
        if (!fileName.isEmpty()) {
            parser.saveToPcap(fileName);
        }
    });

    actionOpen->setEnabled(true);
    actionSave->setEnabled(true);
    // ===end section===

    newSession = fileMenu->addAction("New Session", this, &MainWindow::startNewSession);
    fileMenu->addSeparator();
    fileMenu->addAction("Exit",      this, [](){ qApp->quit(); });

    auto *captureMenu = menuBar->addMenu("Capture");
    captureMenu->addAction("Start", startBtn, &QPushButton::click);
    captureMenu->addAction("Stop",  stopBtn,  &QPushButton::click);

    auto *analyzeMenu = menuBar->addMenu("Analyze");
    analyzeMenu->addAction("Follow Stream", this, [](){
      QMessageBox::information(nullptr,"Analyze","…"); });
    analyzeMenu->addAction("Show Payload Only", this, []() {
        QMessageBox::information(nullptr, "Analyze", "Payload filter view coming soon.");
    });
    auto *statsMenu = menuBar->addMenu("Statistics");
    statsMenu->addAction("Summary", this, [this]() {
        StatsDialog dlg(this);
        dlg.exec(); 
    });
    statsMenu->addAction("GeoOverview", this, [this]() {
        GeoOverviewDialog dlg(&geo, this);
        dlg.exec();
    });


    auto *toolsMenu = menuBar->addMenu("Tools");
    toolsMenu->addAction("Preferences", this, &MainWindow::openPreferences);

    toolsMenu->addSeparator();

    toolsMenu->addAction("Reporting…", this, []() {
        QMessageBox::information(nullptr, "Tools", "PDF/HTML report generation planned.");
    });
    toolsMenu->addAction("Open Logs Folder", this, []() {
        QMessageBox::information(nullptr, "Tools", "Planned");
    });


    auto *viewMenu = menuBar->addMenu("View");
    viewMenu->addAction("Customize coloring…",
                        this, &MainWindow::showColorizeCustomizer);
    viewMenu->addAction("Export Coloring…", this, [this](){
        QString fn = QFileDialog::getSaveFileName(
            this, "Export Coloring", QString(), "JSON (*.json)");
        if (!fn.isEmpty() && packetColorizer.saveRulesToJson(fn)) {
            showColorizeCustomizer();
        }
    });

    viewMenu->addAction("Import Coloring…", this, [this](){
        QString fn = QFileDialog::getOpenFileName(
            this, "Import Coloring", QString(), "JSON (*.json)");
        if (!fn.isEmpty() && packetColorizer.loadRulesFromJson(fn)) {
            packetColorizer.saveRulesToSettings();
            showColorizeCustomizer();
        }
    });
        themeToggleAction = viewMenu->addAction(
        Theme::toggleActionText(),
        this, &MainWindow::toggleTheme
    );
    otherThemesAction = viewMenu->addAction("Other themes…",
                                        this, &MainWindow::showOtherThemesDialog);

    auto *helpMenu = menuBar->addMenu("Help");
    helpMenu->addAction("About", this, [](){
      QMessageBox::about(nullptr,"About","Professional Packet Sniffer\nby Bartosz Malujda");
    });
    // --- Status bar ---
    protocolCombo = new QComboBox(this);
    protocolCombo->setMinimumWidth(100);
    protocolCombo->setToolTip("Top 5 protocols");
    statusBar()->addWidget(protocolCombo);

    packetCountLabel = new QLabel("Packets: 0", this);
    sessionTimeLabel = new QLabel("Time: 00:00:00", this);
    statusBar()->addPermanentWidget(packetCountLabel);
    statusBar()->addPermanentWidget(sessionTimeLabel);

    sessionTimer = new QTimer(this);
    connect(sessionTimer, &QTimer::timeout,
            this, &MainWindow::updateSessionTime);

    packetCount = 0;
    protocolCounts.clear();
    updateProtocolCombo();
}

void MainWindow::listInterfaces() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    {
        QSignalBlocker blocker(ifaceBox);
        ifaceBox->clear();
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            QMessageBox::critical(this, "Error", errbuf);
            return;
        }
        for (auto *d = alldevs; d; d = d->next)
            ifaceBox->addItem(d->name);
        pcap_freealldevs(alldevs);
    }
    const QString preferredInterface = appSettings.defaultInterface();
    if (!preferredInterface.isEmpty()) {
        const int index = ifaceBox->findText(preferredInterface);
        if (index != -1) {
            ifaceBox->setCurrentIndex(index);
            return;
        }
    }
    if (ifaceBox->count() > 0) {
        ifaceBox->setCurrentIndex(0);
    }
}

void MainWindow::openPreferences() {
    QStringList interfaces;
    interfaces.reserve(ifaceBox->count());
    for (int i = 0; i < ifaceBox->count(); ++i) {
        interfaces << ifaceBox->itemText(i);
    }

    PreferencesDialog dlg(appSettings, interfaces, this);
    if (dlg.exec() == QDialog::Accepted) {
        const QString preferredInterface = appSettings.defaultInterface();
        if (!preferredInterface.isEmpty()) {
            const int index = ifaceBox->findText(preferredInterface);
            if (index != -1) {
                ifaceBox->setCurrentIndex(index);
            }
        }
        Theme::applyTheme(appSettings.theme());
        themeToggleAction->setText(Theme::toggleActionText());

        if (appSettings.autoStartCapture() && startBtn->isEnabled() && ifaceBox->count() > 0) {
            QTimer::singleShot(0, startBtn, &QPushButton::click);
        }
    }
}

void MainWindow::showOtherThemesDialog() {
    OtherThemesDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        Theme::applyTheme(dlg.selectedTheme());
    }
}
