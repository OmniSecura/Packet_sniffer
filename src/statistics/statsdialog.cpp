#include "statsdialog.h"
#include "FlowTableModel.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDebug>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelection>
#include <QItemSelectionModel>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMenuBar>
#include <QPixmap>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QTableView>
#include <QTextStream>
#include <QVBoxLayout>

StatsDialog::StatsDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Session Statistics");
    resize(1000, 780);

    // — Menu with Save/Export —
    auto *menuBar  = new QMenuBar(this);
    auto *fileMenu = menuBar->addMenu("File");
    fileMenu->addAction("Save as PNG", this, [this]() {
        QString fn = QFileDialog::getSaveFileName(this,
                            "Save Chart as PNG", "", "*.png");
        if (fn.isEmpty()) return;
        QPixmap pm;
        if (stackedWidget->currentIndex() == 0)
            pm = barChartWidget->grab();
        else if (stackedWidget->currentIndex() == 1)
            pm = lineChartWidget->grab();
        else
            return;
        pm.save(fn);
    });
    fileMenu->addAction("Export CSV", this, [this]() {
        QString fn = QFileDialog::getSaveFileName(this,
                            "Export Data as CSV", "", "*.csv");
        if (fn.isEmpty()) return;
        QFile f(fn);
        if (!f.open(QIODevice::WriteOnly)) {
            qWarning() << "Cannot open" << fn;
            return;
        }
        QTextStream ts(&f);
        int idx = stackedWidget->currentIndex();
        auto quote = [](const QString &value) {
            QString out = value;
            if (out.contains('"'))
                out.replace("\"", "\"\"");
            if (out.contains(',') || out.contains('"')) {
                out.prepend('"');
                out.append('"');
            }
            return out;
        };
        if (idx == 0) {
            ts << "Protocol,Count\n";
            auto plot = barChartWidget->currentPlot();
            for (auto it = plot.constBegin(); it != plot.constEnd(); ++it)
                ts << it.key() << "," << it.value() << "\n";
        } else if (idx == 1) {
            ts << "Interval,Value\n";
            auto pts = lineChartWidget->currentData();
            for (auto &p : pts)
                ts << p.x() << "," << p.y() << "\n";
        } else if (idx == 2) {
            ts << "Protocol,Source,Src Port,Destination,Dst Port,Packets,Bytes,Duration (s),First Seen,Last Seen,Session\n";
            const auto rows = flowModel->currentEntries();
            for (const auto &entry : rows) {
                const QString firstSeen = entry.firstSeen.isValid()
                        ? entry.firstSeen.toString(Qt::ISODate)
                        : QString();
                const QString lastSeen = entry.lastSeen.isValid()
                        ? entry.lastSeen.toString(Qt::ISODate)
                        : QString();
                ts << quote(entry.protocol) << ','
                   << quote(entry.srcAddress) << ','
                   << (entry.srcPort == 0 ? QStringLiteral("-") : QString::number(entry.srcPort)) << ','
                   << quote(entry.dstAddress) << ','
                   << (entry.dstPort == 0 ? QStringLiteral("-") : QString::number(entry.dstPort)) << ','
                   << entry.packets << ','
                   << entry.bytes << ','
                   << entry.durationSeconds << ','
                   << quote(firstSeen) << ','
                   << quote(lastSeen) << ','
                   << quote(entry.sessionLabel)
                   << "\n";
            }
        }
        f.close();
    });

    fileMenu->addAction("Export JSON", this, [this]() {
        QString fn = QFileDialog::getSaveFileName(this,
                            "Export Data as JSON", "", "*.json");
        if (fn.isEmpty()) return;
        QFile f(fn);
        if (!f.open(QIODevice::WriteOnly)) {
            qWarning() << "Cannot open" << fn;
            return;
        }
        QJsonDocument doc;
        int idx = stackedWidget->currentIndex();
        if (idx == 0) {
            QJsonArray arr;
            auto plot = barChartWidget->currentPlot();
            for (auto it = plot.constBegin(); it != plot.constEnd(); ++it) {
                QJsonObject obj;
                obj.insert("protocol", it.key());
                obj.insert("count", static_cast<double>(it.value()));
                arr.append(obj);
            }
            doc = QJsonDocument(arr);
        } else if (idx == 1) {
            QJsonArray arr;
            for (auto &p : lineChartWidget->currentData()) {
                QJsonObject obj;
                obj.insert("x", p.x());
                obj.insert("y", p.y());
                arr.append(obj);
            }
            doc = QJsonDocument(arr);
        } else if (idx == 2) {
            QJsonArray arr;
            const auto rows = flowModel->currentEntries();
            for (const auto &entry : rows) {
                QJsonObject obj;
                obj.insert("protocol", entry.protocol);
                obj.insert("srcAddress", entry.srcAddress);
                obj.insert("srcPort", static_cast<int>(entry.srcPort));
                obj.insert("dstAddress", entry.dstAddress);
                obj.insert("dstPort", static_cast<int>(entry.dstPort));
                obj.insert("packets", static_cast<double>(entry.packets));
                obj.insert("bytes", static_cast<double>(entry.bytes));
                obj.insert("durationSeconds", static_cast<double>(entry.durationSeconds));
                if (entry.firstSeen.isValid())
                    obj.insert("firstSeen", entry.firstSeen.toString(Qt::ISODate));
                if (entry.lastSeen.isValid())
                    obj.insert("lastSeen", entry.lastSeen.toString(Qt::ISODate));
                obj.insert("sessionLabel", entry.sessionLabel);
                arr.append(obj);
            }
            doc = QJsonDocument(arr);
        }
        f.write(doc.toJson());
        f.close();
    });

    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setMenuBar(menuBar);

    // — Chart selection buttons —
    auto *btnLayout = new QHBoxLayout;
    barChartBtn  = new QPushButton(tr("Bar chart"),  this);
    lineChartBtn = new QPushButton(tr("Line chart"), this);
    flowBtn      = new QPushButton(tr("Conversations"), this);
    btnLayout->addWidget(barChartBtn);
    btnLayout->addWidget(lineChartBtn);
    btnLayout->addWidget(flowBtn);
    mainLayout->addLayout(btnLayout);

    // — Filters row —
    optionsBar = new QHBoxLayout;
    mainLayout->addLayout(optionsBar);

    // — Charts —
    barChartWidget  = new BarChart(this);
    barScrollArea   = new QScrollArea(this);
    barScrollArea->setWidgetResizable(true);
    barScrollArea->setWidget(barChartWidget);

    lineChartWidget = new LineChart(this);

    flowModel = new FlowTableModel(this);
    flowTableView = new QTableView(this);
    flowTableView->setModel(flowModel);
    flowTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    flowTableView->setSelectionMode(QAbstractItemView::SingleSelection);
    flowTableView->setAlternatingRowColors(true);
    flowTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    flowTableView->horizontalHeader()->setStretchLastSection(true);

    connect(flowTableView->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, [this](const QItemSelection &selected, const QItemSelection &) {
        if (selected.indexes().isEmpty()) {
            emit flowSelectionCleared();
            return;
        }
        const int row = selected.indexes().first().row();
        auto entry = flowModel->entryAt(row);
        emit flowSelected(entry.protocol,
                          entry.srcAddress, entry.srcPort,
                          entry.dstAddress, entry.dstPort);
    });

    connect(flowModel, &FlowTableModel::sessionsChanged, this, [this]() {
        if (!flowSession) {
            return;
        }
        const QString previous = flowSession->currentText();
        const QSignalBlocker blocker(flowSession);
        flowSession->clear();
        flowSession->addItems(flowModel->availableSessionLabels());
        flowSession->setEnabled(flowSession->count() > 0);
        int idx = flowSession->findText(previous);
        if (idx < 0 && flowSession->count() > 0) {
            idx = 0;
        }
        if (idx >= 0) {
            flowSession->setCurrentIndex(idx);
            flowModel->setSessionIndex(idx);
        } else {
            flowModel->setSessionIndex(-1);
        }
    });

    stackedWidget = new QStackedWidget(this);
    stackedWidget->addWidget(barScrollArea);    // index 0
    stackedWidget->addWidget(lineChartWidget);  // index 1
    stackedWidget->addWidget(flowTableView);    // index 2
    mainLayout->addWidget(stackedWidget);

    connect(barChartBtn,  &QPushButton::clicked, this, [this](){
        stackedWidget->setCurrentIndex(0);
    });
    connect(lineChartBtn, &QPushButton::clicked, this, [this](){
        stackedWidget->setCurrentIndex(1);
    });
    connect(flowBtn, &QPushButton::clicked, this, [this](){
        stackedWidget->setCurrentIndex(2);
    });
    connect(stackedWidget,
            &QStackedWidget::currentChanged,
            this,
            &StatsDialog::updateOptionsBar);

    // — Close button —
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected,
            this, &StatsDialog::reject);
    mainLayout->addWidget(buttons);

    setLayout(mainLayout);

    // Initialize filters for the first (bar) chart
    updateOptionsBar(0);
}

StatsDialog::~StatsDialog() = default;

void StatsDialog::updateOptionsBar(int index)
{
    // Clear any existing widgets
    QLayoutItem *child;
    while ((child = optionsBar->takeAt(0)) != nullptr) {
        if (child->widget())
            child->widget()->deleteLater();
        delete child;
    }

    barFilter = nullptr;
    sessionSel = nullptr;
    sortCombo = nullptr;
    lineMode = nullptr;
    lineSession = nullptr;
    metricCombo = nullptr;
    flowMode = nullptr;
    flowSession = nullptr;
    clearFlowButton = nullptr;

    if (index == 0) {
        // — BarChart filters —

        // Mode selector
        barFilter = new QComboBox(this);
        barFilter->addItems({ "All time", "Current session", "By session" });
        optionsBar->addWidget(barFilter);
        connect(barFilter,
                &QComboBox::currentTextChanged,
                this,
                [this](const QString &t) {
            if (sessionSel) {
                optionsBar->removeWidget(sessionSel);
                sessionSel->deleteLater();
                sessionSel = nullptr;
            }
            if (t == "By session") {
                sessionSel = new QComboBox(this);
                sessionSel->addItems(barChartWidget->availableSessionLabels());
                optionsBar->addWidget(sessionSel);
                connect(sessionSel,
                        QOverload<int>::of(&QComboBox::currentIndexChanged),
                        this,
                        [this](int idx) {
                    barChartWidget->setSessionIndex(idx);
                });
                barChartWidget->setMode(chart::Mode::BySession);
            } else if (t == "Current session") {
                barChartWidget->setMode(chart::Mode::CurrentSession);
            } else {
                barChartWidget->setMode(chart::Mode::AllTime);
            }
        });
        barFilter->setCurrentText("All time");

        // Sort selector
        sortCombo = new QComboBox(this);
        sortCombo->addItems({ "By value", "Alphabetical" });
        optionsBar->addWidget(sortCombo);
        connect(sortCombo,
                &QComboBox::currentTextChanged,
                this,
                [this](const QString &t) {
            barChartWidget->setSortMode(
                t == "Alphabetical"
                  ? BarChart::Alphabetical
                  : BarChart::ByValue
            );
        });
        sortCombo->setCurrentText("By value");

        // Protocols filter
        protocolBtn = new QPushButton("Protocols...", this);
        optionsBar->addWidget(protocolBtn);
        connect(protocolBtn, &QPushButton::clicked, this, [this]() {
            QDialog dlg(this);
            dlg.setWindowTitle("Select Protocols");
            QVBoxLayout layout(&dlg);
            QVector<QCheckBox*> boxes;
            for (auto &p : barChartWidget->availableProtocols()) {
                auto *cb = new QCheckBox(p, &dlg);
                cb->setChecked(true);
                layout.addWidget(cb);
                boxes.append(cb);
            }
            QDialogButtonBox dbb(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                &dlg);
            layout.addWidget(&dbb);
            connect(&dbb, &QDialogButtonBox::accepted,  &dlg, &QDialog::accept);
            connect(&dbb, &QDialogButtonBox::rejected,  &dlg, &QDialog::reject);
            if (dlg.exec() == QDialog::Accepted) {
                QStringList sel;
                for (auto *cb : boxes)
                    if (cb->isChecked())
                        sel << cb->text();
                barChartWidget->setProtocolFilter(sel);
            }
        });

    }
    else if (index == 1) {
        // — LineChart filters —

        // Mode selector
        lineMode = new QComboBox(this);
        lineMode->addItems({ "All time", "Current session", "By session" });
        optionsBar->addWidget(lineMode);
        connect(lineMode,
                QOverload<int>::of(&QComboBox::currentIndexChanged),
                this,
                [this](int idx) {
            if (lineSession) {
                optionsBar->removeWidget(lineSession);
                lineSession->deleteLater();
                lineSession = nullptr;
            }
            if (idx == 2) {  // By session
                lineSession = new QComboBox(this);
                lineSession->addItems(
                    lineChartWidget->availableSessionLabels()
                );
                optionsBar->addWidget(lineSession);
                connect(lineSession,
                        QOverload<int>::of(&QComboBox::currentIndexChanged),
                        this,
                        [this](int sidx) {
                    lineChartWidget->setSessionIndex(sidx);
                });
                lineChartWidget->setMode(chart::Mode::BySession);
            }
            else if (idx == 1) {
                lineChartWidget->setMode(chart::Mode::CurrentSession);
            }
            else {  // All time
                lineChartWidget->setMode(chart::Mode::AllTime);
            }
        });
        lineMode->setCurrentIndex(0);

        // Metric selector
        metricCombo = new QComboBox(this);
        metricCombo->addItems(lineChartWidget->availableMetrics());
        optionsBar->addWidget(metricCombo);
        connect(metricCombo,
                QOverload<int>::of(&QComboBox::currentIndexChanged),
                this,
                [this](int midx) {
            lineChartWidget->setMetric(LineChart::Metric(midx));
        });
        metricCombo->setCurrentIndex(0);

        // Resolution selector
        {
            QComboBox *resCombo = new QComboBox(this);
            resCombo->addItems({ "Seconds", "Minutes", "Hours" });
            optionsBar->addWidget(resCombo);
            connect(resCombo,
                    QOverload<int>::of(&QComboBox::currentIndexChanged),
                    this,
                    [this](int ridx) {
                lineChartWidget->setResolution(
                    LineChart::Resolution(ridx)
                );
            });
            resCombo->setCurrentIndex(0);
        }
    }
    else if (index == 2) {
        flowMode = new QComboBox(this);
        flowMode->addItems({ "All time", "Current session", "By session" });
        optionsBar->addWidget(flowMode);
        connect(flowMode,
                QOverload<int>::of(&QComboBox::currentIndexChanged),
                this,
                [this](int idx) {
            if (flowSession) {
                optionsBar->removeWidget(flowSession);
                flowSession->deleteLater();
                flowSession = nullptr;
            }
            if (idx == 2) {
                flowSession = new QComboBox(this);
                flowSession->addItems(flowModel->availableSessionLabels());
                flowSession->setEnabled(flowSession->count() > 0);
                optionsBar->addWidget(flowSession);
                connect(flowSession,
                        QOverload<int>::of(&QComboBox::currentIndexChanged),
                        this,
                        [this](int sidx) {
                    flowModel->setSessionIndex(sidx);
                    if (flowTableView)
                        flowTableView->clearSelection();
                    emit flowSelectionCleared();
                });
                if (flowSession->count() > 0) {
                    flowSession->setCurrentIndex(0);
                    flowModel->setSessionIndex(0);
                } else {
                    flowModel->setSessionIndex(-1);
                }
            }
            else if (idx == 1) {
                flowModel->setMode(chart::Mode::CurrentSession);
                if (flowTableView)
                    flowTableView->clearSelection();
                emit flowSelectionCleared();
            }
            else {
                flowModel->setMode(chart::Mode::AllTime);
                if (flowTableView)
                    flowTableView->clearSelection();
                emit flowSelectionCleared();
            }
        });
        flowMode->setCurrentIndex(0);

        clearFlowButton = new QPushButton(tr("Clear selection"), this);
        optionsBar->addWidget(clearFlowButton);
        connect(clearFlowButton, &QPushButton::clicked, this, [this]() {
            if (flowTableView)
                flowTableView->clearSelection();
            emit flowSelectionCleared();
        });
    }
}
