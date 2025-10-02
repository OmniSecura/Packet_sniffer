#include "mainwindow_packets.h"
#include "../packets/packethelpers.h"
#include "../../protocols/proto_struct.h"
#include "../PacketTableModel.h"
#include "selectionannotationdialog.h"
#include <algorithm>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

// void MainWindow::onPacketClicked(int row, int /*col*/) { //QTableWidget before QTableView
void MainWindow::onPacketClicked(const QModelIndex &index) {
    int row = index.row();
    detailsTree->setUpdatesEnabled(false);
    detailsTree->clear();

    // const QString srcIp = packetTable->item(row, 2)->text();
    // const QString dstIp = packetTable->item(row, 3)->text();
    // const QByteArray raw = packetTable->item(row, 6)
    //                             ->data(Qt::UserRole)
    //                             .toByteArray(); //QTableWidget before QTableView
    PacketTableRow r = packetModel->row(row);
    const QString srcIp = r.columns.value(2);
    const QString dstIp = r.columns.value(3);
    const QByteArray raw = r.rawData;
    
    const u_char *pkt = reinterpret_cast<const u_char*>(raw.constData());
    
    const auto layers = parser.parseLayers(pkt);
    for (const auto &lay : layers) {
        addLayerToTree(detailsTree, lay);
    }

    // --- Geolocation---
    QStringList isoCodes;
    const auto geoLayers = geo.GeoVector(srcIp, dstIp);
    if (!geoLayers.isEmpty()) {
        QTreeWidgetItem *geoRoot = new QTreeWidgetItem(
            detailsTree,
            QStringList{ "Geographical Information" }
        );
        for (const auto &gs : geoLayers) {
            QTreeWidgetItem *ipNode = new QTreeWidgetItem(
                geoRoot,
                QStringList{ gs.name }
            );
            for (const auto &f : gs.fields) {
                new QTreeWidgetItem(
                    ipNode,
                    QStringList{ f.first, f.second }
                );
            }
            const QString countryName = gs.fields[0].second; // “Country”
            auto it = CountryMap::nameToIso().find(countryName);
            if (it != CountryMap::nameToIso().end())
                isoCodes << *it;
        }
    }

    detailsTree->setUpdatesEnabled(true);
    // optional: detailsTree->expandAll();

    // Map Coloring
    if (!isoCodes.isEmpty())
        mapWidget->highlightCountries(isoCodes);

    // --- Payload hex dump ---
    const auto et = ethType(pkt);
    const int iphdr = (et == ETHERTYPE_IP
                       ? IP_HL(ipv4Hdr(pkt)) * 4
                       : 0);
    const int header_len = linkHdrLen() + iphdr;
    const QByteArray payload = raw.mid(header_len);
    hexEdit->setPlainText(
        parser.toHexAscii(
            reinterpret_cast<const u_char*>(payload.constData()),
            payload.size()
        )
    );
}


void MainWindow::showColorizeCustomizer() {
    QVector<ColoringRule> current = packetColorizer.rules();
    CustomizerDialog dlg(this, std::move(current));

    if (dlg.exec() == QDialog::Accepted) {
        packetColorizer.clearRules();
        for (auto &r : dlg.takeRules())
            packetColorizer.addRule(std::move(r));
        packetColorizer.saveRulesToSettings();
    }
}


QStringList MainWindow::infoColumn(const QStringList &parts, const u_char *pkt)
{
    QStringList infoValues;

    const QString &proto = parts.value(2);
    auto assign = [&](const QStringList &values, int skip = 0) {
        if (!values.isEmpty())
            infoValues = values.mid(skip);
    };

    if (proto == QLatin1String("TCP")) {
        // parseTcp() returns { src, dst, sport, dport,
        //                       seq, ack, hdrlen, flags, win, sum, urp }
        assign(parser.parseTcp(pkt), 4);
    }
    else if (proto == QLatin1String("UDP")) {
        // parseUdp() returns { src, dst, sport, dport, len, sum }
        assign(parser.parseUdp(pkt), 4);
    }
    else if (proto == QLatin1String("ARP")) {
        // parseArp() returns { sip, tip, hrd, pro, hln, pln, op, sha, tha, smac, dmac }
        assign(parser.parseArp(pkt), 2);
    }
    else if (proto == QLatin1String("ICMP")) {
        // parseIcmp() returns { type, code, checksum, identifier, sequence, message }
        assign(parser.parseIcmp(pkt));
    }
    else if (proto == QLatin1String("ICMPv6")) {
        // parseIcmpv6() returns { type, code, checksum, identifier, sequence, message }
        assign(parser.parseIcmpv6(pkt));
    }
    else if (proto == QLatin1String("IGMP")) {
        assign(parser.parseIgmp(pkt));
    }
    else if (proto == QLatin1String("SCTP")) {
        assign(parser.parseSctp(pkt));
    }
    else if (proto == QLatin1String("UDPLITE")) {
        assign(parser.parseUdplite(pkt));
    }
    else if (proto == QLatin1String("GRE")) {
        assign(parser.parseGre(pkt));
    }
    else if (proto == QLatin1String("IPIP")) {
        assign(parser.parseIpip(pkt));
    }
    else if (proto == QLatin1String("OSPF")) {
        assign(parser.parseOspf(pkt));
    }
    else if (proto == QLatin1String("RSVP")) {
        assign(parser.parseRsvp(pkt));
    }
    else if (proto == QLatin1String("PIM")) {
        assign(parser.parsePim(pkt));
    }
    else if (proto == QLatin1String("EGP")) {
        assign(parser.parseEgp(pkt));
    }
    else if (proto == QLatin1String("AH")) {
        assign(parser.parseAh(pkt));
    }
    else if (proto == QLatin1String("ESP")) {
        assign(parser.parseEsp(pkt));
    }
    else if (proto == QLatin1String("MPLS")) {
        assign(parser.parseMpls(pkt));
    }
    else if (proto == QLatin1String("HOPOPTS")) {
        assign(parser.parseIpv6HopByHop(pkt));
    }
    else if (proto == QLatin1String("ROUTING")) {
        assign(parser.parseIpv6Routing(pkt));
    }
    else if (proto == QLatin1String("FRAGMENT")) {
        assign(parser.parseIpv6Fragment(pkt));
    }
    else if (proto == QLatin1String("DSTOPTS")) {
        assign(parser.parseIpv6Destination(pkt));
    }
    else if (proto == QLatin1String("MH")) {
        assign(parser.parseIpv6Mobility(pkt));
    }

    if (infoValues.isEmpty())
        infoValues << QStringLiteral("-");

    return infoValues;
}


void MainWindow::startNewSession(){
    parser.clearBuffer();
    // packetTable->setRowCount(0); //QTableWidget before QTableView
    packetModel->clear();
    detailsTree->clear();
    hexEdit->clear();
    protocolCombo->clear();
    packetCount = 0;
    packetCountLabel->setText("Packets: 0");
    sessionStartTime = QDateTime::currentDateTime();
    updateSessionTime();
    annotations.clear();
}

void MainWindow::saveAnnotationToFile(const PacketAnnotation &annotation)
{
    QDir baseDir(QDir::currentPath());
    const QString folderName = QStringLiteral("reporting");
    if (!baseDir.exists(folderName))
        baseDir.mkpath(folderName);

    if (!baseDir.cd(folderName))
        return;

    QDateTime timestamp = annotation.createdAt.isValid()
        ? annotation.createdAt
        : QDateTime::currentDateTime();

    QString baseName = annotation.title.trimmed();
    if (baseName.isEmpty())
        baseName = timestamp.toString(QStringLiteral("yyyyMMdd_HHmmss"));

    baseName.replace(' ', '_');
    static const QRegularExpression invalidChars(QStringLiteral("[^A-Za-z0-9_-]"));
    baseName.replace(invalidChars, QStringLiteral("_"));
    if (baseName.isEmpty())
        baseName = QStringLiteral("report_%1").arg(timestamp.toString(QStringLiteral("yyyyMMdd_HHmmss")));

    const QString filePath = baseDir.filePath(baseName + QStringLiteral(".json"));
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return;

    QJsonObject root;
    root.insert(QStringLiteral("title"), annotation.title);
    root.insert(QStringLiteral("description"), annotation.description);
    root.insert(QStringLiteral("threatLevel"), annotation.threatLevel);
    root.insert(QStringLiteral("recommendedAction"), annotation.recommendedAction);
    root.insert(QStringLiteral("createdAt"), timestamp.toString(Qt::ISODate));

    QJsonArray tagArray;
    for (const QString &tag : annotation.tags)
        tagArray.append(tag);
    root.insert(QStringLiteral("tags"), tagArray);

    QJsonArray packetArray;
    for (const PacketAnnotationItem &item : annotation.packets) {
        QJsonObject packetObject;
        packetObject.insert(QStringLiteral("row"), item.row);

        QJsonArray packetTags;
        for (const QString &tag : item.tags)
            packetTags.append(tag);
        packetObject.insert(QStringLiteral("tags"), packetTags);

        if (item.color.isValid())
            packetObject.insert(QStringLiteral("color"), item.color.name(QColor::HexArgb));

        PacketTableRow rowData = packetModel->row(item.row);
        packetObject.insert(QStringLiteral("number"), rowData.columns.value(PacketColumns::ColumnNumber));
        packetObject.insert(QStringLiteral("time"), rowData.columns.value(PacketColumns::ColumnTime));
        packetObject.insert(QStringLiteral("source"), rowData.columns.value(PacketColumns::ColumnSource));
        packetObject.insert(QStringLiteral("destination"), rowData.columns.value(PacketColumns::ColumnDestination));
        packetObject.insert(QStringLiteral("protocol"), rowData.columns.value(PacketColumns::ColumnProtocol));
        packetObject.insert(QStringLiteral("info"), rowData.columns.value(PacketColumns::ColumnInfo));

        packetArray.append(packetObject);
    }
    root.insert(QStringLiteral("packets"), packetArray);

    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

void MainWindow::onPacketTableContextMenu(const QPoint &pos)
{
    QModelIndex index = packetTable->indexAt(pos);
    if (!index.isValid()) return;

    if (!packetTable->selectionModel()->isRowSelected(index.row(), QModelIndex())) {
            packetTable->selectionModel()->clearSelection();
            packetTable->selectRow(index.row());
        }

    QList<int> rows;
    for (const QModelIndex &idx : packetTable->selectionModel()->selectedRows())
        rows.append(idx.row());
    if (rows.isEmpty()) return;

    QStringList srcList, dstList, protoList;
    for (int r : rows) {
        PacketTableRow rowData = packetModel->row(r);
        srcList  << rowData.columns.value(2);
        dstList  << rowData.columns.value(3);
        protoList << rowData.columns.value(4).toLower();
    }
    srcList.removeDuplicates();
    dstList.removeDuplicates();
    protoList.removeDuplicates();

    QMenu menu(this);
    QAction *reportAct = menu.addAction(tr("Reporting…"));
    QMenu *filterMenu = menu.addMenu(tr("Filter…"));
    QAction *srcAct   = filterMenu->addAction(tr("Source Host"));
    QAction *dstAct   = filterMenu->addAction(tr("Destination Host"));
    QAction *protoAct = filterMenu->addAction(tr("Protocol"));

    QAction *chosen = menu.exec(packetTable->viewport()->mapToGlobal(pos));
    if (!chosen) return;

    if (chosen == reportAct) {
        QVector<SelectionAnnotationDialog::PacketSummary> packetSummaries;
        packetSummaries.reserve(rows.size());
        for (int r : rows) {
            PacketTableRow rowData = packetModel->row(r);
            SelectionAnnotationDialog::PacketSummary summary;
            summary.row = r;
            summary.number = rowData.columns.value(PacketColumns::ColumnNumber);
            summary.time = rowData.columns.value(PacketColumns::ColumnTime);
            summary.source = rowData.columns.value(PacketColumns::ColumnSource);
            summary.destination = rowData.columns.value(PacketColumns::ColumnDestination);
            summary.protocol = rowData.columns.value(PacketColumns::ColumnProtocol);
            summary.info = rowData.columns.value(PacketColumns::ColumnInfo);
            packetSummaries.append(summary);
        }

        SelectionAnnotationDialog dlg(packetSummaries, this);
        if (dlg.exec() == QDialog::Accepted) {
            SelectionAnnotationDialog::Result dialogResult = dlg.result();
            PacketAnnotation annotation;
            annotation.title = dialogResult.title;
            annotation.description = dialogResult.description;
            annotation.tags = dialogResult.tags;
            annotation.threatLevel = dialogResult.threatLevel;
            annotation.recommendedAction = dialogResult.recommendedAction;
            annotation.createdAt = QDateTime::currentDateTime();

            QVector<PacketAnnotationItem> packetItems;
            packetItems.reserve(dialogResult.packets.size());
            for (const auto &packetResult : dialogResult.packets) {
                PacketAnnotationItem item;
                item.row = packetResult.row;
                item.tags = packetResult.tags;
                item.color = packetResult.color;
                packetItems.append(item);
                packetModel->setRowBackground(item.row, item.color);
            }
            annotation.packets = packetItems;

            annotations.append(annotation);
            saveAnnotationToFile(annotation);

            const QString titleText = annotation.title.isEmpty()
                ? tr("selection report")
                : QStringLiteral("'%1'").arg(annotation.title);
            statusBar()->showMessage(tr("Saved reporting for %1 packets as %2")
                                         .arg(annotation.packets.size())
                                         .arg(titleText),
                                     6000);
        }
    } else if (chosen == srcAct) {
        QStringList parts;
        for (const QString &s : srcList)
            parts << QString("src host %1").arg(s);
        filterEdit->setText(parts.join(" or "));
    } else if (chosen == dstAct) {
        QStringList parts;
        for (const QString &d : dstList)
            parts << QString("dst host %1").arg(d);
        filterEdit->setText(parts.join(" or "));
    } else if (chosen == protoAct) {
        filterEdit->setText(protoList.join(" or "));
    }
}

void MainWindow::toggleTheme()
{
    Theme::toggleTheme();
    themeToggleAction->setText(Theme::toggleActionText());
}

void MainWindow::updateSessionTime() {
    qint64 secs = sessionStartTime.secsTo(
                     QDateTime::currentDateTime()
                   );
    QTime t(0,0);
    t = t.addSecs(secs);
    sessionTimeLabel->setText(
        QString("Time: %1").arg(t.toString("HH:mm:ss"))
    );
}


static QList<QPair<QString,int>> sortedList(const QMap<QString,int> &map) {
    QList<QPair<QString,int>> lst;
    for (auto it = map.constBegin(); it != map.constEnd(); ++it)
        lst.append(qMakePair(it.key(), it.value()));
    std::sort(lst.begin(), lst.end(),
        [](auto &a, auto &b){ return a.second > b.second; });
    return lst;
}
void MainWindow::updateProtocolCombo()
{
    protocolCombo->clear();
    auto lst = sortedList(protocolCounts);

    int N = qMin(5, lst.size());
    for (int i = 0; i < N; ++i) {
        protocolCombo->addItem(
            QString("%1: %2")
                .arg(lst[i].first)
                .arg(lst[i].second)
        );
    }
    for (int i = N; i < 5; ++i)
        protocolCombo->addItem(QStringLiteral("—: 0"));

    QList<QPair<QString,int>> top5;
    top5.reserve(N);
    for (int i = 0; i < N; ++i) {
        top5.append(lst[i]);
    }

    if (pieChart) {
        pieChart->setData(top5);
    }
}

void MainWindow::addLayerToTree(QTreeWidget *tree, const PacketLayer &lay) {
    auto *layer = new QTreeWidgetItem(tree, QStringList{ lay.name });
    auto groups = groupByCategory(lay.fields);
    for (auto it = groups.cbegin(); it != groups.cend(); ++it) {
        auto *category = new QTreeWidgetItem(layer, QStringList{ it.key() });
        for (auto &f : it.value()) {
            new QTreeWidgetItem(category, QStringList{ f.label, f.value });
        }
    }
}
