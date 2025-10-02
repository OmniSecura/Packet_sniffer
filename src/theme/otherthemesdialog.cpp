#include "otherthemesdialog.h"
#include "ui_otherthemesdialog.h"
#include "theme.h"

OtherThemesDialog::OtherThemesDialog(QWidget *parent)
  : QDialog(parent), ui(new Ui::OtherThemesDialog)
{
    ui->setupUi(this);
    loadList();

    connect(ui->themeList, &QListWidget::currentTextChanged,
            this, &OtherThemesDialog::on_themeList_currentTextChanged);

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

    connect(ui->addCustom, &QPushButton::clicked,
            this, &OtherThemesDialog::on_addCustom_clicked);
    connect(ui->removeCustom, &QPushButton::clicked,
            this, &OtherThemesDialog::on_removeCustom_clicked);
}

OtherThemesDialog::~OtherThemesDialog()
{
    delete ui;
}

QString OtherThemesDialog::selectedTheme() const
{
    return ui->themeList->currentItem()
         ? ui->themeList->currentItem()->text()
         : QString();
}

void OtherThemesDialog::loadList()
{
    ui->themeList->clear();
    for (auto &n : builtIns)
        ui->themeList->addItem(n);
    QSettings s("Engineering","PacketSniffer");
    for (auto &n : s.value("CustomThemes/List").toStringList())
        ui->themeList->addItem(n);
    if (ui->themeList->count())
        ui->themeList->setCurrentRow(0);
}

void OtherThemesDialog::saveCustomNames()
{
    QSettings s("Engineering","PacketSniffer");
    QStringList customs;
    for (int i = builtIns.size(); i < ui->themeList->count(); ++i)
        customs << ui->themeList->item(i)->text();
    s.setValue("CustomThemes/List", customs);
}

void OtherThemesDialog::on_themeList_currentTextChanged(const QString &name)
{
    // live‐preview
    QPalette p = Theme::paletteForName(name);
    ui->previewGroup->setAutoFillBackground(true);
    ui->previewGroup->setPalette(p);
    for (auto w : ui->previewGroup->findChildren<QWidget*>()) {
        w->setAutoFillBackground(true);
        w->setPalette(p);
    }
}

void OtherThemesDialog::on_addCustom_clicked()
{
    bool ok;
    QString name = QInputDialog::getText(this,
        "New Theme", "Enter theme name:",
        QLineEdit::Normal, {}, &ok);
    if (!ok || name.isEmpty()) return;

    QColor win = QColorDialog::getColor(Qt::white, this, "Window frame");
    if (!win.isValid()) return;
    QColor bg = QColorDialog::getColor(Qt::white, this, "Window background");
    if (!bg.isValid()) return;
    QColor text = QColorDialog::getColor(Qt::black, this, "Text color");
    if (!text.isValid()) return;
    QColor btnBg = QColorDialog::getColor(bg,    this, "Button background");
    if (!btnBg.isValid()) return;
    QColor btnText = QColorDialog::getColor(text, this, "Button text color");
    if (!btnText.isValid()) return;

    Theme::saveCustomPalette(name, win, bg, text, btnBg, btnText);

    QSettings s("Engineering","PacketSniffer");
    auto list = s.value("CustomThemes/List").toStringList();
    if (!list.contains(name)) {
        list << name;
        s.setValue("CustomThemes/List", list);
    }

    loadList();
    saveCustomNames();
    auto items = ui->themeList->findItems(name, Qt::MatchExactly);
    if (!items.isEmpty())
        ui->themeList->setCurrentItem(items.first());
}

void OtherThemesDialog::on_removeCustom_clicked()
{
    auto item = ui->themeList->currentItem();
    if (!item) return;
    QString name = item->text();
    if (builtIns.contains(name)) return;

    QSettings s("Engineering","PacketSniffer");
    s.remove(QString("CustomThemes/%1").arg(name));
    auto list = s.value("CustomThemes/List").toStringList();
    list.removeAll(name);
    s.setValue("CustomThemes/List", list);

    loadList();
    saveCustomNames();
}
