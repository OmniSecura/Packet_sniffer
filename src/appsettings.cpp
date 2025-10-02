#include "appsettings.h"

#include <QtGlobal>
#include <QStandardPaths>

namespace {
constexpr const char *kOrganization = "Engineering";
constexpr const char *kApplication  = "PacketSniffer";
constexpr const char *kDefaultInterfaceKey = "Preferences/DefaultInterface";
constexpr const char *kAutoStartKey        = "Preferences/AutoStartCapture";
constexpr const char *kThemeKey            = "Theme";
constexpr const char *kReportsDirKey       = "Preferences/ReportsDirectory";
constexpr const char *kPromiscuousKey      = "Preferences/Promiscuous";
constexpr const char *kDefaultFilterKey    = "Preferences/DefaultFilter";
}

AppSettings::AppSettings()
    : ownedSettings(std::make_unique<QSettings>(kOrganization, kApplication)),
      settingsPtr(ownedSettings.get())
{
}

AppSettings::AppSettings(QSettings &settings)
    : settingsPtr(&settings)
{
}

QString AppSettings::defaultInterface() const {
    return settings().value(kDefaultInterfaceKey).toString();
}

void AppSettings::setDefaultInterface(const QString &iface) {
    settings().setValue(kDefaultInterfaceKey, iface);
}

bool AppSettings::autoStartCapture() const {
    return settings().value(kAutoStartKey, false).toBool();
}

void AppSettings::setAutoStartCapture(bool enabled) {
    settings().setValue(kAutoStartKey, enabled);
}

QString AppSettings::theme() const {
    return settings().value(kThemeKey, QStringLiteral("Light")).toString();
}

void AppSettings::setTheme(const QString &theme) {
    settings().setValue(kThemeKey, theme);
}

QString AppSettings::reportsDirectory() const {
    const QString fallback = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    return settings().value(kReportsDirKey, fallback).toString();
}

void AppSettings::setReportsDirectory(const QString &path) {
    settings().setValue(kReportsDirKey, path);
}

bool AppSettings::promiscuousMode() const {
    return settings().value(kPromiscuousKey, true).toBool();
}

void AppSettings::setPromiscuousMode(bool enabled) {
    settings().setValue(kPromiscuousKey, enabled);
}

QString AppSettings::defaultFilter() const {
    return settings().value(kDefaultFilterKey).toString();
}

void AppSettings::setDefaultFilter(const QString &filter) {
    settings().setValue(kDefaultFilterKey, filter);
}

QSettings &AppSettings::settings() const {
    Q_ASSERT(settingsPtr);
    return *settingsPtr;
}
