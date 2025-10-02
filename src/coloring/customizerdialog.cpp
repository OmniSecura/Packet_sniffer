#include "customizerdialog.h"
#include <QListWidget>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QDialogButtonBox>
#include <QInputDialog>
#include <QColorDialog>

CustomizerDialog::CustomizerDialog(QWidget *parent,
                                   QVector<ColoringRule> initialRules)
  : QDialog(parent),
    m_rules(std::move(initialRules))
{
    setWindowTitle(tr("Customize Coloring Rules"));
    resize(400, 300);

    m_listWidget = new QListWidget(this);
    m_addBtn     = new QPushButton(tr("Add…"), this);
    m_editBtn    = new QPushButton(tr("Edit…"), this);
    m_removeBtn  = new QPushButton(tr("Remove"), this);

    connect(m_addBtn,    &QPushButton::clicked, this, &CustomizerDialog::onAdd);
    connect(m_editBtn,   &QPushButton::clicked, this, &CustomizerDialog::onEdit);
    connect(m_removeBtn, &QPushButton::clicked, this, &CustomizerDialog::onRemove);

    auto *btnLayout = new QHBoxLayout;
    btnLayout->addWidget(m_addBtn);
    btnLayout->addWidget(m_editBtn);
    btnLayout->addWidget(m_removeBtn);

    auto *dialogButtons = new QDialogButtonBox(
        QDialogButtonBox::Ok|QDialogButtonBox::Cancel,
        Qt::Horizontal, this);
    connect(dialogButtons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(dialogButtons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto *mainLayout = new QVBoxLayout;
    mainLayout->addWidget(m_listWidget);
    mainLayout->addLayout(btnLayout);
    mainLayout->addWidget(dialogButtons);
    setLayout(mainLayout);

    rebuildList();
}

CustomizerDialog::~CustomizerDialog() = default;

void CustomizerDialog::rebuildList() {
    m_listWidget->clear();
    for (auto &r : m_rules) {
        auto *item = new QListWidgetItem(r.bpfExpression, m_listWidget);
        item->setBackground(r.color);
        item->setForeground(r.color.lightness() < 128
                            ? Qt::white
                            : Qt::black);
    }
}

void CustomizerDialog::onAdd() {
    bool ok=false;
    QString expr = QInputDialog::getText(
        this, tr("New rule"), tr("BPF expression:"),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || expr.isEmpty()) return;

    QColor c = QColorDialog::getColor(Qt::yellow, this);
    if (!c.isValid()) return;

    ColoringRule r; r.bpfExpression = expr; r.color = c;
    m_rules.push_back(std::move(r));
    rebuildList();
}

void CustomizerDialog::onEdit() {
    int idx = m_listWidget->currentRow();
    if (idx<0) return;

    bool ok=false;
    QString expr = QInputDialog::getText(
        this, tr("Edit rule"), tr("BPF expression:"),
        QLineEdit::Normal, m_rules[idx].bpfExpression, &ok);
    if (!ok || expr.isEmpty()) return;

    QColor c = QColorDialog::getColor(m_rules[idx].color, this);
    if (!c.isValid()) return;

    m_rules[idx].bpfExpression = expr;
    m_rules[idx].color         = c;
    rebuildList();
}

void CustomizerDialog::onRemove() {
    int idx = m_listWidget->currentRow();
    if (idx<0) return;
    m_rules.removeAt(idx);
    rebuildList();
}

QVector<ColoringRule> CustomizerDialog::takeRules() {
    return std::move(m_rules);
}
