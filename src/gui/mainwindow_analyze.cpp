#include "mainwindow.h"
#include "../PacketTableModel.h"
#include "../../packets/packethelpers.h"

#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStatusBar>
#include <QTabWidget>
#include <QTextStream>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

MainWindow::FlowTuple MainWindow::flowTupleFromPacket(const PacketTableRow &row) const
{
    FlowTuple tuple;
    tuple.srcAddr = row.columns.value(PacketColumns::ColumnSource);
    tuple.dstAddr = row.columns.value(PacketColumns::ColumnDestination);
    tuple.protocol = row.columns.value(PacketColumns::ColumnProtocol).toUpper();
    tuple.ipv6 = tuple.srcAddr.contains(QLatin1Char(':')) || tuple.dstAddr.contains(QLatin1Char(':'));

    if (row.rawData.isEmpty()) {
        tuple.valid = !tuple.srcAddr.isEmpty() && !tuple.dstAddr.isEmpty();
        return tuple;
    }

    const u_char *pkt = reinterpret_cast<const u_char*>(row.rawData.constData());
    const uint16_t etherType = ethType(pkt, row.linkType);
    char srcBuffer[INET6_ADDRSTRLEN] = {0};
    char dstBuffer[INET6_ADDRSTRLEN] = {0};

    if (etherType == ETHERTYPE_IP) {
        const sniff_ip *ip = ipv4Hdr(pkt, row.linkType);
        if (!ip)
            return tuple;

        if (inet_ntop(AF_INET, &ip->ip_src, srcBuffer, sizeof(srcBuffer)))
            tuple.srcAddr = QString::fromLatin1(srcBuffer);
        if (inet_ntop(AF_INET, &ip->ip_dst, dstBuffer, sizeof(dstBuffer)))
            tuple.dstAddr = QString::fromLatin1(dstBuffer);

        tuple.ipProto = ip->ip_p;
        tuple.protocol = protoName(ip->ip_p);
        tuple.ipv6 = false;
        tuple.valid = true;

        if (ip->ip_p == IPPROTO_TCP) {
            TcpSegmentView view = tcpSegmentView(pkt, row.linkType);
            if (view.header) {
                tuple.hasPorts = true;
                tuple.srcPort = ntohs(view.header->th_sport);
                tuple.dstPort = ntohs(view.header->th_dport);
            }
        } else if (ip->ip_p == IPPROTO_UDP) {
            UdpDatagramView view = udpDatagramView(pkt, row.linkType);
            if (view.header) {
                tuple.hasPorts = true;
                tuple.srcPort = ntohs(view.header->uh_sport);
                tuple.dstPort = ntohs(view.header->uh_dport);
            }
        }
    }
    else if (etherType == ETHERTYPE_IPV6) {
        const sniff_ipv6 *ip6 = ipv6Hdr(pkt, row.linkType);
        if (!ip6)
            return tuple;

        if (inet_ntop(AF_INET6, &ip6->ip6_src, srcBuffer, sizeof(srcBuffer)))
            tuple.srcAddr = QString::fromLatin1(srcBuffer);
        if (inet_ntop(AF_INET6, &ip6->ip6_dst, dstBuffer, sizeof(dstBuffer)))
            tuple.dstAddr = QString::fromLatin1(dstBuffer);

        tuple.ipProto = ip6->ip6_nxt;
        tuple.protocol = protoName(ip6->ip6_nxt);
        tuple.ipv6 = true;
        tuple.valid = true;

        if (ip6->ip6_nxt == IPPROTO_TCP) {
            TcpSegmentView view = tcpSegmentView(pkt, row.linkType);
            if (view.header) {
                tuple.hasPorts = true;
                tuple.srcPort = ntohs(view.header->th_sport);
                tuple.dstPort = ntohs(view.header->th_dport);
            }
        } else if (ip6->ip6_nxt == IPPROTO_UDP) {
            UdpDatagramView view = udpDatagramView(pkt, row.linkType);
            if (view.header) {
                tuple.hasPorts = true;
                tuple.srcPort = ntohs(view.header->uh_sport);
                tuple.dstPort = ntohs(view.header->uh_dport);
            }
        }
    }
    else {
        tuple.valid = !tuple.srcAddr.isEmpty() && !tuple.dstAddr.isEmpty();
        return tuple;
    }

    if (tuple.protocol.isEmpty())
        tuple.protocol = row.columns.value(PacketColumns::ColumnProtocol).toUpper();

    return tuple;
}

int MainWindow::flowDirection(const FlowTuple &base, const FlowTuple &candidate) const
{
    if (!base.valid || !candidate.valid)
        return 0;

    if (base.ipv6 != candidate.ipv6)
        return 0;

    if (base.ipProto && candidate.ipProto && base.ipProto != candidate.ipProto)
        return 0;

    if (!base.protocol.isEmpty() && !candidate.protocol.isEmpty() && base.protocol != candidate.protocol)
        return 0;

    if (base.hasPorts != candidate.hasPorts)
        return 0;

    const bool portsMatch = !base.hasPorts
        || (base.srcPort == candidate.srcPort && base.dstPort == candidate.dstPort);
    const bool portsMatchReverse = !base.hasPorts
        || (base.srcPort == candidate.dstPort && base.dstPort == candidate.srcPort);

    if (base.srcAddr == candidate.srcAddr
        && base.dstAddr == candidate.dstAddr
        && portsMatch)
        return 1;

    if (base.srcAddr == candidate.dstAddr
        && base.dstAddr == candidate.srcAddr
        && portsMatchReverse)
        return -1;

    return 0;
}

QString MainWindow::formatEndpoint(const QString &addr, quint16 port, bool includePort) const
{
    if (!includePort)
        return addr;

    if (addr.contains(QLatin1Char(':')))
        return QStringLiteral("[%1]:%2").arg(addr).arg(port);

    return QStringLiteral("%1:%2").arg(addr).arg(port);
}

QString MainWindow::conversationFilter(const FlowTuple &flow) const
{
    if (!flow.valid)
        return {};

    const QString ipKeyword = flow.ipv6 ? QStringLiteral("ip6") : QStringLiteral("ip");
    QString protoKeyword;
    if (flow.protocol == QLatin1String("TCP") || flow.protocol == QLatin1String("UDP"))
        protoKeyword = flow.protocol.toLower();

    const QString portKeyword = flow.hasPorts ? protoKeyword : QString();

    QStringList clauses;
    auto appendClause = [&](const QString &srcAddr, quint16 srcPort,
                            const QString &dstAddr, quint16 dstPort) {
        QString clause = QStringLiteral("%1 src %2 and %1 dst %3")
                             .arg(ipKeyword, srcAddr, dstAddr);
        if (!portKeyword.isEmpty()) {
            clause += QStringLiteral(" and %1 src port %2 and %1 dst port %3")
                          .arg(portKeyword)
                          .arg(srcPort)
                          .arg(dstPort);
        }
        clauses << clause;
    };

    appendClause(flow.srcAddr, flow.srcPort, flow.dstAddr, flow.dstPort);
    appendClause(flow.dstAddr, flow.dstPort, flow.srcAddr, flow.srcPort);

    QString filter = clauses.join(QStringLiteral(") or ("));
    filter.prepend(QLatin1Char('('));
    filter.append(QLatin1Char(')'));

    if (!protoKeyword.isEmpty())
        filter.prepend(protoKeyword + QStringLiteral(" and "));

    return filter;
}

QByteArray MainWindow::extractPayload(const PacketTableRow &row) const
{
    if (row.rawData.isEmpty())
        return {};

    const u_char *pkt = reinterpret_cast<const u_char*>(row.rawData.constData());
    const uint16_t etherType = ethType(pkt, row.linkType);

    if (etherType == ETHERTYPE_IP) {
        const sniff_ip *ip = ipv4Hdr(pkt, row.linkType);
        if (!ip)
            return {};

        const quint8 proto = ip->ip_p;
        if (proto == IPPROTO_TCP) {
            TcpSegmentView view = tcpSegmentView(pkt, row.linkType);
            if (view.header && view.payload && view.payloadLength > 0)
                return QByteArray(reinterpret_cast<const char*>(view.payload), view.payloadLength);
            return {};
        }
        if (proto == IPPROTO_UDP) {
            UdpDatagramView view = udpDatagramView(pkt, row.linkType);
            if (view.header && view.payload && view.payloadLength > 0)
                return QByteArray(reinterpret_cast<const char*>(view.payload), view.payloadLength);
            return {};
        }

        const int offset = linkHdrLen(row.linkType) + ipv4HdrLen(pkt, row.linkType);
        int payloadLen = ntohs(ip->ip_len) - ipv4HdrLen(pkt, row.linkType);
        if (payloadLen <= 0 || offset >= row.rawData.size())
            return {};
        payloadLen = std::min(payloadLen, row.rawData.size() - offset);
        return row.rawData.mid(offset, payloadLen);
    }

    if (etherType == ETHERTYPE_IPV6) {
        const sniff_ipv6 *ip6 = ipv6Hdr(pkt, row.linkType);
        if (!ip6)
            return {};

        const quint8 proto = ip6->ip6_nxt;
        if (proto == IPPROTO_TCP) {
            TcpSegmentView view = tcpSegmentView(pkt, row.linkType);
            if (view.header && view.payload && view.payloadLength > 0)
                return QByteArray(reinterpret_cast<const char*>(view.payload), view.payloadLength);
            return {};
        }
        if (proto == IPPROTO_UDP) {
            UdpDatagramView view = udpDatagramView(pkt, row.linkType);
            if (view.header && view.payload && view.payloadLength > 0)
                return QByteArray(reinterpret_cast<const char*>(view.payload), view.payloadLength);
            return {};
        }

        const int offset = linkHdrLen(row.linkType) + static_cast<int>(sizeof(sniff_ipv6));
        int payloadLen = ntohs(ip6->ip6_plen);
        if (payloadLen <= 0 || offset >= row.rawData.size())
            return {};
        payloadLen = std::min(payloadLen, row.rawData.size() - offset);
        return row.rawData.mid(offset, payloadLen);
    }

    const int offset = linkHdrLen(row.linkType);
    if (offset >= row.rawData.size())
        return {};

    return row.rawData.mid(offset);
}

QString MainWindow::printablePayload(const QByteArray &payload) const
{
    QString text;
    text.reserve(payload.size());
    for (unsigned char ch : payload) {
        if (ch == '\n') {
            text.append(QLatin1Char('\n'));
        } else if (ch >= 0x20 && ch <= 0x7E) {
            text.append(QChar(ch));
        } else if (ch == '\t') {
            text.append(QStringLiteral("\t"));
        } else {
            text.append(QLatin1Char('.'));
        }
    }
    return text;
}

void MainWindow::followSelectedStream()
{
    if (!packetTable || !packetModel)
        return;

    QItemSelectionModel *selection = packetTable->selectionModel();
    if (!selection || selection->selectedRows().isEmpty()) {
        QMessageBox::information(this, tr("Follow Stream"),
                                 tr("Select at least one packet to follow a stream."));
        return;
    }

    QList<int> rows;
    for (const QModelIndex &idx : selection->selectedRows())
        rows.append(idx.row());
    std::sort(rows.begin(), rows.end());

    PacketTableRow anchorRow = packetModel->row(rows.first());
    FlowTuple base = flowTupleFromPacket(anchorRow);
    if (!base.valid) {
        QMessageBox::warning(this, tr("Follow Stream"),
                              tr("Unable to determine the conversation for the selected packet."));
        return;
    }

    struct StreamEntry {
        FlowTuple flow;
        bool forward = true;
        QString time;
        QString info;
        QByteArray payload;
        int rowIndex = 0;
        int totalLength = 0;
    };

    QVector<StreamEntry> entries;
    entries.reserve(packetModel->rowCount());

    qint64 totalBytes = 0;
    qint64 totalPayload = 0;

    const int rowCount = packetModel->rowCount();
    for (int i = 0; i < rowCount; ++i) {
        PacketTableRow rowData = packetModel->row(i);
        FlowTuple tuple = flowTupleFromPacket(rowData);
        int direction = flowDirection(base, tuple);
        if (direction == 0)
            continue;

        StreamEntry entry;
        entry.flow = tuple;
        entry.forward = direction > 0;
        entry.time = rowData.columns.value(PacketColumns::ColumnTime);
        entry.info = rowData.columns.value(PacketColumns::ColumnInfo);
        entry.payload = extractPayload(rowData);
        entry.rowIndex = i;
        entry.totalLength = rowData.rawData.size();

        entries.append(entry);
        totalBytes += entry.totalLength;
        totalPayload += entry.payload.size();
    }

    if (entries.isEmpty()) {
        QMessageBox::information(this, tr("Follow Stream"),
                                 tr("No other packets found for this conversation."));
        return;
    }

    const QString srcEndpoint = formatEndpoint(base.srcAddr, base.srcPort, base.hasPorts);
    const QString dstEndpoint = formatEndpoint(base.dstAddr, base.dstPort, base.hasPorts);
    const QString protocol = base.protocol.isEmpty() ? tr("Unknown") : base.protocol;

    QString textContent;
    QString hexContent;
    textContent.reserve(entries.size() * 120);
    hexContent.reserve(entries.size() * 160);

    for (const StreamEntry &entry : entries) {
        const QString entrySrc = formatEndpoint(entry.flow.srcAddr, entry.flow.srcPort,
                                                base.hasPorts && entry.flow.hasPorts);
        const QString entryDst = formatEndpoint(entry.flow.dstAddr, entry.flow.dstPort,
                                                base.hasPorts && entry.flow.hasPorts);
        const QString header = tr("#%1 [%2] %3 -> %4 (%5 bytes, payload %6)")
                                   .arg(entry.rowIndex + 1)
                                   .arg(entry.time)
                                   .arg(entrySrc)
                                   .arg(entryDst)
                                   .arg(entry.totalLength)
                                   .arg(entry.payload.size());
        textContent += header + QLatin1Char('\n');
        if (!entry.info.isEmpty())
            textContent += tr("Info: %1\n").arg(entry.info);
        if (!entry.payload.isEmpty())
            textContent += printablePayload(entry.payload) + QLatin1Char('\n');
        textContent += QLatin1Char('\n');

        hexContent += header + QLatin1Char('\n');
        if (!entry.payload.isEmpty()) {
            hexContent += parser.toHexAscii(
                reinterpret_cast<const u_char*>(entry.payload.constData()),
                entry.payload.size());
        } else {
            hexContent += tr("[no payload]");
        }
        hexContent += QLatin1String("\n\n");
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Follow Stream"));

    auto *layout = new QVBoxLayout(&dialog);

    auto *summaryLabel = new QLabel(
        tr("Stream %1 ↔ %2 (%3)\n%4 packets | %5 bytes total | %6 payload bytes")
            .arg(srcEndpoint, dstEndpoint, protocol)
            .arg(entries.size())
            .arg(totalBytes)
            .arg(totalPayload),
        &dialog);
    summaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(summaryLabel);

    auto *tabs = new QTabWidget(&dialog);
    auto *textView = new QPlainTextEdit(textContent, &dialog);
    textView->setReadOnly(true);
    auto *hexView = new QPlainTextEdit(hexContent, &dialog);
    hexView->setReadOnly(true);
    tabs->addTab(textView, tr("Text"));
    tabs->addTab(hexView, tr("Hex dump"));
    layout->addWidget(tabs, 1);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto *copyTextBtn = buttonBox->addButton(tr("Copy Text"), QDialogButtonBox::ActionRole);
    auto *copyHexBtn = buttonBox->addButton(tr("Copy Hex"), QDialogButtonBox::ActionRole);
    auto *exportTextBtn = buttonBox->addButton(tr("Export Text…"), QDialogButtonBox::ActionRole);
    auto *exportHexBtn = buttonBox->addButton(tr("Export Hex…"), QDialogButtonBox::ActionRole);

    QString filter = conversationFilter(base);
    QPushButton *applyFilterBtn = nullptr;
    if (!filter.isEmpty()) {
        applyFilterBtn = buttonBox->addButton(tr("Apply Filter"), QDialogButtonBox::ActionRole);
    }

    layout->addWidget(buttonBox);

    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(copyTextBtn, &QPushButton::clicked, this, [textView]() {
        QApplication::clipboard()->setText(textView->toPlainText());
    });
    connect(copyHexBtn, &QPushButton::clicked, this, [hexView]() {
        QApplication::clipboard()->setText(hexView->toPlainText());
    });
    connect(exportTextBtn, &QPushButton::clicked, this, [this, textView]() {
        const QString path = QFileDialog::getSaveFileName(nullptr, tr("Export Text"),
                                                          QString(), tr("Text files (*.txt);;All files (*.*)"));
        if (path.isEmpty())
            return;
        QFile file(path);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << textView->toPlainText();
        }
    });
    connect(exportHexBtn, &QPushButton::clicked, this, [this, hexView]() {
        const QString path = QFileDialog::getSaveFileName(nullptr, tr("Export Hex"),
                                                          QString(), tr("Text files (*.txt);;All files (*.*)"));
        if (path.isEmpty())
            return;
        QFile file(path);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << hexView->toPlainText();
        }
    });
    if (applyFilterBtn) {
        connect(applyFilterBtn, &QPushButton::clicked, this, [this, filter]() {
            filterEdit->setText(filter);
            statusBar()->showMessage(tr("Applied conversation filter."), 5000);
        });
    }

    dialog.resize(800, 600);
    dialog.exec();
}

void MainWindow::showPayloadOnlyDialog()
{
    if (!packetTable || !packetModel)
        return;

    QItemSelectionModel *selection = packetTable->selectionModel();
    if (!selection || selection->selectedRows().isEmpty()) {
        QMessageBox::information(this, tr("Payload Viewer"),
                                 tr("Select one or more packets to inspect their payload."));
        return;
    }

    QList<int> rows;
    for (const QModelIndex &idx : selection->selectedRows())
        rows.append(idx.row());
    std::sort(rows.begin(), rows.end());

    QString textContent;
    QString hexContent;
    qint64 totalPayload = 0;
    qint64 totalBytes = 0;

    for (int rowIndex : rows) {
        PacketTableRow rowData = packetModel->row(rowIndex);
        QByteArray payload = extractPayload(rowData);
        const QString src = rowData.columns.value(PacketColumns::ColumnSource);
        const QString dst = rowData.columns.value(PacketColumns::ColumnDestination);
        const QString protocol = rowData.columns.value(PacketColumns::ColumnProtocol);
        const QString time = rowData.columns.value(PacketColumns::ColumnTime);
        const QString info = rowData.columns.value(PacketColumns::ColumnInfo);

        const QString header = tr("#%1 [%2] %3 -> %4 (%5, payload %6)")
                                   .arg(rowIndex + 1)
                                   .arg(time)
                                   .arg(src)
                                   .arg(dst)
                                   .arg(protocol)
                                   .arg(payload.size());
        textContent += header + QLatin1Char('\n');
        if (!info.isEmpty())
            textContent += tr("Info: %1\n").arg(info);
        if (!payload.isEmpty())
            textContent += printablePayload(payload) + QLatin1Char('\n');
        textContent += QLatin1Char('\n');

        hexContent += header + QLatin1Char('\n');
        if (!payload.isEmpty()) {
            hexContent += parser.toHexAscii(
                reinterpret_cast<const u_char*>(payload.constData()),
                payload.size());
        } else {
            hexContent += tr("[no payload]");
        }
        hexContent += QLatin1String("\n\n");

        totalPayload += payload.size();
        totalBytes += rowData.rawData.size();
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Payload Viewer"));

    auto *layout = new QVBoxLayout(&dialog);
    auto *summaryLabel = new QLabel(
        tr("%1 packets selected | %2 bytes total | %3 payload bytes")
            .arg(rows.size())
            .arg(totalBytes)
            .arg(totalPayload),
        &dialog);
    summaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(summaryLabel);

    auto *tabs = new QTabWidget(&dialog);
    auto *textView = new QPlainTextEdit(textContent, &dialog);
    textView->setReadOnly(true);
    auto *hexView = new QPlainTextEdit(hexContent, &dialog);
    hexView->setReadOnly(true);
    tabs->addTab(textView, tr("Text"));
    tabs->addTab(hexView, tr("Hex dump"));
    layout->addWidget(tabs, 1);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto *copyTextBtn = buttonBox->addButton(tr("Copy Text"), QDialogButtonBox::ActionRole);
    auto *copyHexBtn = buttonBox->addButton(tr("Copy Hex"), QDialogButtonBox::ActionRole);
    auto *exportTextBtn = buttonBox->addButton(tr("Export Text…"), QDialogButtonBox::ActionRole);
    auto *exportHexBtn = buttonBox->addButton(tr("Export Hex…"), QDialogButtonBox::ActionRole);
    layout->addWidget(buttonBox);

    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(copyTextBtn, &QPushButton::clicked, this, [textView]() {
        QApplication::clipboard()->setText(textView->toPlainText());
    });
    connect(copyHexBtn, &QPushButton::clicked, this, [hexView]() {
        QApplication::clipboard()->setText(hexView->toPlainText());
    });
    connect(exportTextBtn, &QPushButton::clicked, this, [this, textView]() {
        const QString path = QFileDialog::getSaveFileName(nullptr, tr("Export Text"),
                                                          QString(), tr("Text files (*.txt);;All files (*.*)"));
        if (path.isEmpty())
            return;
        QFile file(path);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << textView->toPlainText();
        }
    });
    connect(exportHexBtn, &QPushButton::clicked, this, [this, hexView]() {
        const QString path = QFileDialog::getSaveFileName(nullptr, tr("Export Hex"),
                                                          QString(), tr("Text files (*.txt);;All files (*.*)"));
        if (path.isEmpty())
            return;
        QFile file(path);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << hexView->toPlainText();
        }
    });

    dialog.resize(700, 550);
    dialog.exec();
}

void MainWindow::showConversationSummary()
{
    if (!packetTable || !packetModel)
        return;

    QItemSelectionModel *selection = packetTable->selectionModel();
    if (!selection || selection->selectedRows().isEmpty()) {
        QMessageBox::information(this, tr("Conversation Summary"),
                                 tr("Select a packet to build a conversation summary."));
        return;
    }

    QList<int> rows;
    for (const QModelIndex &idx : selection->selectedRows())
        rows.append(idx.row());
    std::sort(rows.begin(), rows.end());

    PacketTableRow anchorRow = packetModel->row(rows.first());
    FlowTuple base = flowTupleFromPacket(anchorRow);
    if (!base.valid) {
        QMessageBox::warning(this, tr("Conversation Summary"),
                              tr("Unable to determine the conversation for the selected packet."));
        return;
    }

    int totalPackets = 0;
    int forwardPackets = 0;
    int reversePackets = 0;
    quint64 totalBytes = 0;
    quint64 forwardBytes = 0;
    quint64 reverseBytes = 0;
    quint64 totalPayload = 0;
    quint64 forwardPayload = 0;
    quint64 reversePayload = 0;
    double firstTime = std::numeric_limits<double>::max();
    double lastTime = 0.0;

    const int rowCount = packetModel->rowCount();
    for (int i = 0; i < rowCount; ++i) {
        PacketTableRow rowData = packetModel->row(i);
        FlowTuple tuple = flowTupleFromPacket(rowData);
        int direction = flowDirection(base, tuple);
        if (direction == 0)
            continue;

        ++totalPackets;
        totalBytes += rowData.rawData.size();
        QByteArray payload = extractPayload(rowData);
        totalPayload += payload.size();

        bool forward = direction > 0;
        if (forward) {
            ++forwardPackets;
            forwardBytes += rowData.rawData.size();
            forwardPayload += payload.size();
        } else {
            ++reversePackets;
            reverseBytes += rowData.rawData.size();
            reversePayload += payload.size();
        }

        bool ok = false;
        double timeValue = rowData.columns.value(PacketColumns::ColumnTime).toDouble(&ok);
        if (ok) {
            firstTime = std::min(firstTime, timeValue);
            lastTime = std::max(lastTime, timeValue);
        }
    }

    if (totalPackets == 0) {
        QMessageBox::information(this, tr("Conversation Summary"),
                                 tr("No packets were found for the selected conversation."));
        return;
    }

    const double duration = lastTime > firstTime ? (lastTime - firstTime) : 0.0;
    const double packetsPerSecond = duration > 0.0 ? totalPackets / duration : totalPackets;
    const double avgPacketSize = totalPackets > 0 ? static_cast<double>(totalBytes) / totalPackets : 0.0;

    const QString srcEndpoint = formatEndpoint(base.srcAddr, base.srcPort, base.hasPorts);
    const QString dstEndpoint = formatEndpoint(base.dstAddr, base.dstPort, base.hasPorts);
    const QString protocol = base.protocol.isEmpty() ? tr("Unknown") : base.protocol;
    const QString filter = conversationFilter(base);

    QString summary;
    QTextStream stream(&summary);
    stream << tr("Conversation between %1 and %2 (%3)")
                  .arg(srcEndpoint, dstEndpoint, protocol)
           << "\n";
    stream << tr("Total packets: %1 (forward %2 / reverse %3)")
                  .arg(totalPackets)
                  .arg(forwardPackets)
                  .arg(reversePackets)
           << "\n";
    stream << tr("Total bytes: %1 (forward %2 / reverse %3)")
                  .arg(totalBytes)
                  .arg(forwardBytes)
                  .arg(reverseBytes)
           << "\n";
    stream << tr("Payload bytes: %1 (forward %2 / reverse %3)")
                  .arg(totalPayload)
                  .arg(forwardPayload)
                  .arg(reversePayload)
           << "\n";
    stream << tr("Duration: %1 s, packets/s: %2, avg packet: %3 bytes")
                  .arg(QString::number(duration, 'f', 3))
                  .arg(QString::number(packetsPerSecond, 'f', 3))
                  .arg(QString::number(avgPacketSize, 'f', 1))
           << "\n";
    if (!filter.isEmpty()) {
        stream << tr("Capture filter: %1").arg(filter) << "\n";
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Conversation Summary"));

    auto *layout = new QVBoxLayout(&dialog);
    auto *summaryView = new QPlainTextEdit(summary, &dialog);
    summaryView->setReadOnly(true);
    layout->addWidget(summaryView);

    QLineEdit *filterLine = nullptr;
    if (!filter.isEmpty()) {
        filterLine = new QLineEdit(filter, &dialog);
        filterLine->setReadOnly(true);
        filterLine->setCursorPosition(0);
        layout->addWidget(filterLine);
    }

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto *copySummaryBtn = buttonBox->addButton(tr("Copy Summary"), QDialogButtonBox::ActionRole);
    QPushButton *copyFilterBtn = nullptr;
    if (filterLine) {
        copyFilterBtn = buttonBox->addButton(tr("Copy Filter"), QDialogButtonBox::ActionRole);
    }
    layout->addWidget(buttonBox);

    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(copySummaryBtn, &QPushButton::clicked, this, [summaryView]() {
        QApplication::clipboard()->setText(summaryView->toPlainText());
    });
    if (copyFilterBtn && filterLine) {
        connect(copyFilterBtn, &QPushButton::clicked, this, [filterLine]() {
            filterLine->selectAll();
            QApplication::clipboard()->setText(filterLine->text());
        });
    }

    dialog.resize(500, 350);
    dialog.exec();
}

void MainWindow::highlightConversationPackets()
{
    if (!packetTable || !packetModel)
        return;

    QItemSelectionModel *selection = packetTable->selectionModel();
    if (!selection || selection->selectedRows().isEmpty()) {
        QMessageBox::information(this, tr("Highlight Stream"),
                                 tr("Select a packet from the conversation you want to highlight."));
        return;
    }

    QList<int> rows;
    for (const QModelIndex &idx : selection->selectedRows())
        rows.append(idx.row());
    std::sort(rows.begin(), rows.end());

    PacketTableRow anchorRow = packetModel->row(rows.first());
    FlowTuple base = flowTupleFromPacket(anchorRow);
    if (!base.valid) {
        QMessageBox::warning(this, tr("Highlight Stream"),
                              tr("Unable to determine the conversation for the selected packet."));
        return;
    }

    int highlighted = 0;
    const QColor highlightColor(255, 244, 200, 255);

    const int rowCount = packetModel->rowCount();
    for (int i = 0; i < rowCount; ++i) {
        PacketTableRow rowData = packetModel->row(i);
        FlowTuple tuple = flowTupleFromPacket(rowData);
        if (flowDirection(base, tuple) == 0)
            continue;
        packetModel->setRowBackground(i, highlightColor);
        ++highlighted;
    }

    if (highlighted == 0) {
        QMessageBox::information(this, tr("Highlight Stream"),
                                 tr("No packets were highlighted."));
    } else {
        statusBar()->showMessage(
            tr("Highlighted %1 packets for the selected conversation.").arg(highlighted),
            5000);
    }
}

void MainWindow::resetPacketHighlights()
{
    if (!packetModel)
        return;

    const int rowCount = packetModel->rowCount();
    if (rowCount == 0)
        return;

    for (int i = 0; i < rowCount; ++i) {
        PacketTableRow rowData = packetModel->row(i);
        pcap_pkthdr hdr{};
        hdr.caplen = hdr.len = rowData.rawData.size();
        const u_char *pkt = reinterpret_cast<const u_char*>(rowData.rawData.constData());
        QColor color = packetColorizer.colorFor(&hdr, pkt);
        packetModel->setRowBackground(i, color);
    }

    statusBar()->showMessage(tr("Restored analyzer highlights."), 4000);
}
