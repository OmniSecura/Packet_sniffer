#include "selectionannotationdialog.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QColorDialog>

#include <algorithm>

SelectionAnnotationDialog::SelectionAnnotationDialog(const QVector<PacketSummary> &packets,
                                                     QWidget *parent)
    : QDialog(parent)
    , m_packets(packets)
{
    setWindowTitle(tr("Report Selection"));
    setModal(true);

    m_summaryLabel = new QLabel(this);
    if (!m_packets.isEmpty()) {
        QVector<int> rows;
        rows.reserve(m_packets.size());
        for (const auto &pkt : m_packets)
            rows.append(pkt.row);
        std::sort(rows.begin(), rows.end());

        QString summary;
        if (rows.size() == 1) {
            summary = tr("Packet #%1").arg(rows.first() + 1);
        } else {
            summary = tr("Packets #%1 – #%2 (%3 items)")
                          .arg(rows.first() + 1)
                          .arg(rows.last() + 1)
                          .arg(rows.size());
        }
        m_summaryLabel->setText(summary);
    }

    m_packetTable = new QTableWidget(this);
    m_packetTable->setColumnCount(8);
    m_packetTable->setHorizontalHeaderLabels({
        tr("No."),
        tr("Time"),
        tr("Source"),
        tr("Destination"),
        tr("Protocol"),
        tr("Info"),
        tr("Tags"),
        tr("Highlight")
    });
    m_packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_packetTable->horizontalHeader()->setStretchLastSection(true);
    m_packetTable->verticalHeader()->setVisible(false);
    m_packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_packetTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    m_packetTable->setRowCount(m_packets.size());
    m_packetColors.resize(m_packets.size(), QColor(255, 232, 128));
    m_packetTagEdits.resize(m_packets.size());
    m_packetColorButtons.resize(m_packets.size());

    for (int row = 0; row < m_packets.size(); ++row) {
        const PacketSummary &pkt = m_packets.at(row);

        auto insertItem = [this, row](int column, const QString &text) {
            auto *item = new QTableWidgetItem(text);
            item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
            m_packetTable->setItem(row, column, item);
        };

        insertItem(0, pkt.number);
        insertItem(1, pkt.time);
        insertItem(2, pkt.source);
        insertItem(3, pkt.destination);
        insertItem(4, pkt.protocol);
        insertItem(5, pkt.info);

        auto *tagEdit = new QLineEdit(this);
        tagEdit->setPlaceholderText(tr("Tags for packet %1").arg(pkt.number));
        m_packetTagEdits[row] = tagEdit;
        m_packetTable->setCellWidget(row, 6, tagEdit);

        auto *colorButton = new QPushButton(tr("Choose…"), this);
        m_packetColorButtons[row] = colorButton;
        updateColorButton(row);
        m_packetTable->setCellWidget(row, 7, colorButton);
        connect(colorButton, &QPushButton::clicked, this, [this, row]() {
            chooseColorForRow(row);
        });
    }

    m_titleEdit = new QLineEdit(this);
    m_titleEdit->setPlaceholderText(tr("Short title for this report"));

    m_descriptionEdit = new QTextEdit(this);
    m_descriptionEdit->setPlaceholderText(tr("Describe why this sequence matters…"));
    m_descriptionEdit->setMinimumHeight(100);

    m_threatCombo = new QComboBox(this);
    m_threatCombo->addItems({
        tr("Informational"),
        tr("Benign"),
        tr("Suspicious"),
        tr("Malicious"),
        tr("Critical")
    });

    m_tagsEdit = new QLineEdit(this);
    m_tagsEdit->setPlaceholderText(tr("Global tags (comma separated)"));

    m_actionCombo = new QComboBox(this);
    m_actionCombo->addItems({
        tr("No immediate action"),
        tr("Investigate further"),
        tr("Block related traffic"),
        tr("Notify response team"),
        tr("Escalate incident")
    });

    m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                       Qt::Horizontal,
                                       this);
    connect(m_buttonBox, &QDialogButtonBox::accepted, this, &SelectionAnnotationDialog::accept);
    connect(m_buttonBox, &QDialogButtonBox::rejected, this, &SelectionAnnotationDialog::reject);

    auto *form = new QFormLayout;
    form->addRow(tr("Title"), m_titleEdit);
    form->addRow(tr("Description"), m_descriptionEdit);
    form->addRow(tr("Threat level"), m_threatCombo);
    form->addRow(tr("Global tags"), m_tagsEdit);
    form->addRow(tr("Recommended action"), m_actionCombo);

    auto *layout = new QVBoxLayout;
    if (!m_summaryLabel->text().isEmpty())
        layout->addWidget(m_summaryLabel);
    layout->addWidget(m_packetTable);
    layout->addLayout(form);
    layout->addWidget(m_buttonBox);

    setLayout(layout);
}

SelectionAnnotationDialog::Result SelectionAnnotationDialog::result() const
{
    Result res;
    res.title = m_titleEdit->text();
    res.description = m_descriptionEdit->toPlainText();
    res.threatLevel = m_threatCombo->currentText();
    res.recommendedAction = m_actionCombo->currentText();

    QStringList baseTags = splitTags(m_tagsEdit->text());
    const QString autoTag = defaultTagForThreat();
    if (!autoTag.isEmpty())
        baseTags.prepend(autoTag);
    baseTags.removeDuplicates();
    res.tags = baseTags;

    res.packets.reserve(m_packets.size());
    for (int i = 0; i < m_packets.size(); ++i) {
        Result::PacketDetail detail;
        detail.row = m_packets.at(i).row;

        QStringList perPacketTags = baseTags;
        if (i < m_packetTagEdits.size() && m_packetTagEdits.at(i)) {
            const QString text = m_packetTagEdits.at(i)->text();
            const QStringList extra = splitTags(text);
            for (const QString &tag : extra)
                perPacketTags.append(tag);
        }
        perPacketTags.removeDuplicates();
        detail.tags = perPacketTags;

        if (i < m_packetColors.size())
            detail.color = m_packetColors.at(i);

        res.packets.append(detail);
    }

    return res;
}

void SelectionAnnotationDialog::chooseColorForRow(int row)
{
    if (row < 0 || row >= m_packetColors.size())
        return;

    const QColor current = m_packetColors.value(row);
    const QColor chosen = QColorDialog::getColor(current, this, tr("Choose highlight color"));
    if (!chosen.isValid())
        return;

    m_packetColors[row] = chosen;
    updateColorButton(row);
}

QStringList SelectionAnnotationDialog::splitTags(const QString &text) const
{
    QStringList tags;
    const QStringList parts = text.split(',', Qt::SkipEmptyParts);
    for (const QString &part : parts) {
        const QString trimmed = part.trimmed();
        if (!trimmed.isEmpty())
            tags << trimmed;
    }
    return tags;
}

QString SelectionAnnotationDialog::defaultTagForThreat() const
{
    const QString threat = m_threatCombo->currentText();
    if (threat.compare(tr("Benign"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("safe");
    }
    if (threat.compare(tr("Suspicious"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("suspicious");
    }
    if (threat.compare(tr("Malicious"), Qt::CaseInsensitive) == 0 ||
        threat.compare(tr("Critical"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("malware");
    }
    return QString();
}

void SelectionAnnotationDialog::updateColorButton(int row)
{
    if (row < 0 || row >= m_packetColorButtons.size())
        return;

    QPushButton *button = m_packetColorButtons.at(row);
    if (!button)
        return;

    const QColor color = m_packetColors.value(row, QColor(255, 232, 128));
    const QString foreground = (color.lightness() < 128)
        ? QStringLiteral("white")
        : QStringLiteral("black");
    const QString style = QStringLiteral("background-color: %1; color: %2;")
                              .arg(color.name())
                              .arg(foreground);
    button->setStyleSheet(style);
}
