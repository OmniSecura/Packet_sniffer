#include "selectionannotationdialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QColorDialog>
#include <algorithm>

SelectionAnnotationDialog::SelectionAnnotationDialog(const QVector<int> &rows, QWidget *parent)
    : QDialog(parent)
    , m_rows(rows)
    , m_color(QColor(255, 232, 128))
{
    setWindowTitle(tr("Annotate Packet Selection"));
    setModal(true);

    m_summaryLabel = new QLabel(this);
    if (!m_rows.isEmpty()) {
        QVector<int> sorted = m_rows;
        std::sort(sorted.begin(), sorted.end());
        QString summary;
        if (sorted.size() == 1) {
            summary = tr("Packet #%1").arg(sorted.first() + 1);
        } else {
            summary = tr("Packets #%1 – #%2 (%3 items)")
                          .arg(sorted.first() + 1)
                          .arg(sorted.last() + 1)
                          .arg(sorted.size());
        }
        m_summaryLabel->setText(summary);
    }

    m_titleEdit = new QLineEdit(this);
    m_titleEdit->setPlaceholderText(tr("Short title for this annotation"));

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
    m_tagsEdit->setPlaceholderText(tr("Additional tags (comma separated)"));

    m_actionCombo = new QComboBox(this);
    m_actionCombo->addItems({
        tr("No immediate action"),
        tr("Investigate further"),
        tr("Block related traffic"),
        tr("Notify response team"),
        tr("Escalate incident")
    });

    m_colorButton = new QPushButton(this);
    m_colorButton->setText(tr("Choose color"));
    updateColorPreview();
    connect(m_colorButton, &QPushButton::clicked,
            this, &SelectionAnnotationDialog::chooseColor);

    m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                       Qt::Horizontal,
                                       this);
    connect(m_buttonBox, &QDialogButtonBox::accepted, this, &SelectionAnnotationDialog::accept);
    connect(m_buttonBox, &QDialogButtonBox::rejected, this, &SelectionAnnotationDialog::reject);

    auto *form = new QFormLayout;
    form->addRow(tr("Selection"), m_summaryLabel);
    form->addRow(tr("Title"), m_titleEdit);
    form->addRow(tr("Description"), m_descriptionEdit);
    form->addRow(tr("Threat level"), m_threatCombo);
    form->addRow(tr("Tags"), m_tagsEdit);
    form->addRow(tr("Recommended action"), m_actionCombo);
    form->addRow(tr("Highlight"), m_colorButton);

    auto *layout = new QVBoxLayout;
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

    QStringList tags;
    const QString baseTag = defaultTagForThreat();
    if (!baseTag.isEmpty())
        tags << baseTag;

    const QString extra = m_tagsEdit->text();
    for (const QString &tag : extra.split(',', Qt::SkipEmptyParts)) {
        QString trimmed = tag.trimmed();
        if (!trimmed.isEmpty())
            tags << trimmed;
    }
    tags.removeDuplicates();
    res.tags = tags;

    res.color = m_color;

    return res;
}

void SelectionAnnotationDialog::chooseColor()
{
    const QColor chosen = QColorDialog::getColor(m_color, this, tr("Choose highlight color"));
    if (chosen.isValid()) {
        m_color = chosen;
        updateColorPreview();
    }
}

void SelectionAnnotationDialog::updateColorPreview()
{
    const QString style = QStringLiteral("background-color: %1; color: %2;")
                              .arg(m_color.name())
                              .arg((m_color.lightness() < 128) ? QStringLiteral("white")
                                                               : QStringLiteral("black"));
    m_colorButton->setStyleSheet(style);
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
