#include "mainwindow_sniffing.h"
#include "../PacketTableModel.h"

#include <pcap.h>
#include <QtGlobal>

void MainWindow::startSniffing() {
    startBtn->setEnabled(false);
    stopBtn->setEnabled(true);
    actionOpen->setEnabled(false);
    actionSave->setEnabled(false);
    newSession->setEnabled(false);

    // Reset :
    // packetTable->setRowCount(0);
    // detailsTree->clear();
    // hexEdit->clear();

    if (stats) {
        stats.reset();
    }
    sessionStartTime = QDateTime::currentDateTime();
    stats = std::make_unique<Statistics>(sessionStartTime);

    sessionTimer->start(1000);
    updateSessionTime();

    if (statsTimer) {
        statsTimer->stop();
        statsTimer->deleteLater();
        statsTimer = nullptr;
    }
    statsTimer = new QTimer(this);
    connect(statsTimer, &QTimer::timeout, this, [this]() {
        if (stats) {
            stats->SaveStatsToJson(Statistics::defaultSessionsDir());
        }
    });
    statsTimer->start(1000);

    worker = new PacketWorker(ifaceBox->currentText(),
                              filterEdit->text(),
                              promiscBox->isChecked());
    workerThread = new QThread;
    worker->moveToThread(workerThread);

    connect(workerThread, &QThread::started,
            worker, &PacketWorker::process);
    connect(worker, &PacketWorker::newPacket,
            this, &MainWindow::handlePacket);
    connect(worker, &PacketWorker::linkTypeChanged,
            this, [this](int linkType, bpf_u_int32 netmask) {
                packetColorizer.setLinkType(linkType, netmask);
            });
    connect(workerThread, &QThread::finished,
            worker, &QObject::deleteLater);
    connect(workerThread, &QThread::finished,
            workerThread, &QObject::deleteLater);

    workerThread->start();
}

void MainWindow::stopSniffing() {
    startBtn->setEnabled(true);
    stopBtn->setEnabled(false);
    actionOpen->setEnabled(true);
    actionSave->setEnabled(true);
    newSession->setEnabled(true);
    sessionTimer->stop();

    if (worker)       worker->stop();
    if (workerThread) {
        workerThread->quit();
        workerThread->wait();
        worker = nullptr;
        workerThread = nullptr;
    }

    if (statsTimer) {
        statsTimer->stop();
        statsTimer->deleteLater();
        statsTimer = nullptr;
    }
    if (stats) {
        persistCurrentSession();
        stats.reset();
    }
}

void MainWindow::handlePacket(const QByteArray &raw,
                              const QStringList &infos,
                              int linkType)
{
    if (packetColorizer.linkType() != linkType) {
        packetColorizer.setLinkType(linkType, 0);
    }
    // == TIME ==
    QDateTime pktTime = QDateTime::currentDateTime();
    qint64 elapsedMs = sessionStartTime.msecsTo(pktTime);
    double elapsedSec = elapsedMs / 1000.0;
    QString time = QString::number(elapsedSec, 'f', 3);
    // ==========

    // int row = packetTable->rowCount();
    // packetTable->insertRow(row);

    // packetTable->setItem(row, 0,
    //     new QTableWidgetItem(QString::number(row+1)));
    // packetTable->setItem(row, 1,
    //     new QTableWidgetItem(time));  //QTableWidget before QTableView
    int row = packetModel->rowCount();
    PacketTableRow tableRow;
    tableRow.columns << QString::number(row + 1)
                     << time;

    const u_char *pkt = reinterpret_cast<const u_char*>(raw.constData());
    auto parts = parser.packetSummary(pkt, raw.size(), linkType);
    // parts = { srcIP, dstIP, protoName, lengthStr }
    // for (int c = 2; c < 6; ++c) {
    //     packetTable->setItem(row, c,
    //         new QTableWidgetItem(parts.value(c-2)));  //QTableWidget before QTableView
    // }

    tableRow.columns << parts.value(0)
                 << parts.value(1)
                 << parts.value(2)
                 << parts.value(3);

    const QString src = parts.value(0);
    const QString dst = parts.value(1);
    const QString proto = parts.value(2);

    quint16 srcPort = 0;
    quint16 dstPort = 0;
    auto extractPorts = [&](const QStringList &values, int srcIndex, int dstIndex) {
        if (values.size() > qMax(srcIndex, dstIndex)) {
            bool ok = false;
            quint16 parsed = values.at(srcIndex).toUShort(&ok);
            srcPort = ok ? parsed : 0;
            ok = false;
            parsed = values.at(dstIndex).toUShort(&ok);
            dstPort = ok ? parsed : 0;
        }
    };

    if (proto == QLatin1String("TCP")) {
        extractPorts(parser.parseTcp(pkt, linkType), 2, 3);
    } else if (proto == QLatin1String("UDP")) {
        extractPorts(parser.parseUdp(pkt, linkType), 2, 3);
    } else if (proto == QLatin1String("SCTP")) {
        extractPorts(parser.parseSctp(pkt, linkType), 2, 3);
    } else if (proto == QLatin1String("UDPLITE")) {
        extractPorts(parser.parseUdplite(pkt, linkType), 2, 3);
    }

    tableRow.protocol = proto;
    tableRow.srcAddress = src;
    tableRow.dstAddress = dst;
    tableRow.srcPort = srcPort;
    tableRow.dstPort = dstPort;

    QStringList infoValues = infoColumn(parts, pkt, linkType);

    // auto *infoItem = new QTableWidgetItem(infoValues.join("  "));
    // infoItem->setData(Qt::UserRole, raw);
    // packetTable->setItem(row, 6, infoItem);  //QTableWidget before QTableView
    tableRow.columns << infoValues.join("  ");
    tableRow.rawData = raw;
    tableRow.linkType = linkType;

    pcap_pkthdr hdr{{ infos[0].toLongLong(), 0 },
                    (bpf_u_int32)raw.size(),
                    (bpf_u_int32)raw.size()};
    QColor bg = packetColorizer.colorFor(&hdr, pkt);
    
    tableRow.background = bg;

    packetModel->addPacket(tableRow);
    //   for (int c = 0; c < packetTable->columnCount(); ++c)
    //     packetTable->item(row,c)->setBackground(bg);  //QTableWidget before QTableView

    packetTable->scrollToBottom();

    ++packetCount;
    packetCountLabel->setText(
        QString("Packets: %1").arg(packetCount)
    );

    protocolCounts[proto] += 1;
    //qint64 elapsed = sessionStartTime.secsTo(QDateTime::currentDateTime());
    //int sec = static_cast<int>(elapsed);
    //statsProtocolPerSecond[sec][proto]++;
    //statsConnectionsPerSecond[sec].insert(qMakePair(parts.value(0), parts.value(1)))
    //statsPacketsPerSecond[sec]++;
    //statsBytesPerSecond[sec] += raw.size();
    quint64 pktSize   = static_cast<quint64>(raw.size());

    if (stats) {
        stats->recordPacket(pktTime, proto, src, srcPort, dst, dstPort, pktSize);
    }

    if (packetTable && m_activeFlowFilter.has_value()) {
        bool visible = matchesFlowFilter(tableRow);
        packetTable->setRowHidden(row, !visible);
    }

    updateProtocolCombo();
}

void MainWindow::onFilterTextChanged(const QString &text) {
    if (worker) {
        QMetaObject::invokeMethod(worker, "updateFilter",
                                  Qt::QueuedConnection,
                                  Q_ARG(QString, text));
    }
}
