#include "preferencesdialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QWidget>
#include <QVBoxLayout>

PreferencesDialog::PreferencesDialog(AppSettings &settings,
                                     const QStringList &interfaces,
                                     QWidget *parent)
    : QDialog(parent),
      settings(settings)
{
    setWindowTitle(tr("Preferences"));
    setModal(true);

    auto *mainLayout = new QVBoxLayout(this);
    auto *formLayout = new QFormLayout;

    interfaceCombo = new QComboBox(this);
    populateInterfaces(interfaces);
    formLayout->addRow(tr("Default interface"), interfaceCombo);

    autoStartCheck = new QCheckBox(tr("Start capturing automatically"), this);
    autoStartCheck->setChecked(settings.autoStartCapture());
    formLayout->addRow(QString(), autoStartCheck);

    themeCombo = new QComboBox(this);
    populateThemes();
    formLayout->addRow(tr("Theme"), themeCombo);

    reportsDirEdit = new QLineEdit(settings.reportsDirectory(), this);
    auto *browseButton = new QPushButton(tr("Browse…"), this);
    auto *reportsLayout = new QHBoxLayout;
    reportsLayout->setContentsMargins(0, 0, 0, 0);
    reportsLayout->addWidget(reportsDirEdit);
    reportsLayout->addWidget(browseButton);

    auto *reportsWidget = new QWidget(this);
    reportsWidget->setLayout(reportsLayout);
    formLayout->addRow(tr("Reports directory"), reportsWidget);

    connect(browseButton, &QPushButton::clicked,
            this, &PreferencesDialog::chooseReportsDirectory);

    mainLayout->addLayout(formLayout);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                           Qt::Horizontal, this);
    connect(buttonBox, &QDialogButtonBox::accepted,
            this, &PreferencesDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected,
            this, &PreferencesDialog::reject);
    mainLayout->addWidget(buttonBox);
}

void PreferencesDialog::accept() {
    settings.setDefaultInterface(interfaceCombo->currentText());
    settings.setAutoStartCapture(autoStartCheck->isChecked());
    settings.setTheme(themeCombo->currentText());
    settings.setReportsDirectory(reportsDirEdit->text());

    QDialog::accept();
}

void PreferencesDialog::chooseReportsDirectory() {
    const QString dir = QFileDialog::getExistingDirectory(
        this,
        tr("Select reports directory"),
        reportsDirEdit->text().isEmpty() ? settings.reportsDirectory()
                                         : reportsDirEdit->text());
    if (!dir.isEmpty()) {
        reportsDirEdit->setText(dir);
    }
}

void PreferencesDialog::populateInterfaces(const QStringList &interfaces) {
    interfaceCombo->addItems(interfaces);

    const QString currentInterface = settings.defaultInterface();
    if (currentInterface.isEmpty()) {
        return;
    }

    int index = interfaceCombo->findText(currentInterface);
    if (index == -1) {
        interfaceCombo->addItem(currentInterface);
        index = interfaceCombo->findText(currentInterface);
    }
    if (index >= 0) {
        interfaceCombo->setCurrentIndex(index);
    }
}

void PreferencesDialog::populateThemes() {
    const QStringList builtInThemes = { QStringLiteral("Light"),
                                        QStringLiteral("Dark"),
                                        QStringLiteral("Greenish"),
                                        QStringLiteral("Black+Orange") };

    for (const QString &themeName : builtInThemes) {
        if (themeCombo->findText(themeName) == -1) {
            themeCombo->addItem(themeName);
        }
    }

    const QString currentTheme = settings.theme();
    if (!currentTheme.isEmpty() && themeCombo->findText(currentTheme) == -1) {
        themeCombo->addItem(currentTheme);
    }

    int themeIndex = themeCombo->findText(currentTheme);
    if (themeIndex < 0 && !builtInThemes.isEmpty()) {
        themeIndex = themeCombo->findText(QStringLiteral("Light"));
    }
    if (themeIndex >= 0) {
        themeCombo->setCurrentIndex(themeIndex);
    }
}
