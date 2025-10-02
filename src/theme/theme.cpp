#include "theme.h"

namespace Theme {
static bool g_dark = false;

// built-ins
static QPalette buildGreenish() {
    QPalette p;
    p.setColor(QPalette::Window,    QColor(220,255,220));
    p.setColor(QPalette::Base,      QColor(245,255,245));
    p.setColor(QPalette::Text,      QColor(20,80,20));
    p.setColor(QPalette::Button,    QColor(200,240,200));
    p.setColor(QPalette::ButtonText,QColor(10,60,10));
    return p;
}

static QPalette buildBlackOrange() {
    QPalette p;
    p.setColor(QPalette::Window,    QColor(30,30,30));
    p.setColor(QPalette::Base,      QColor(45,45,45));
    p.setColor(QPalette::Text,      QColor(255,165,0));
    p.setColor(QPalette::Button,    QColor(50,50,50));
    p.setColor(QPalette::ButtonText,QColor(255,140,0));
    return p;
}

static QPalette loadPalette(const QString &key) {
    QSettings s("Engineering","PacketSniffer");
    auto raw = s.value(key).toByteArray();
    QJsonObject o = QJsonDocument::fromJson(raw).object();
    QPalette p;
    if (o.contains("Window"))     p.setColor(QPalette::Window,    QColor(o["Window"].toString()));
    if (o.contains("Base"))       p.setColor(QPalette::Base,      QColor(o["Base"].toString()));
    if (o.contains("Text"))       p.setColor(QPalette::Text,      QColor(o["Text"].toString()));
    if (o.contains("Button"))     p.setColor(QPalette::Button,    QColor(o["Button"].toString()));
    if (o.contains("ButtonText")) p.setColor(QPalette::ButtonText,QColor(o["ButtonText"].toString()));
    return p;
}

void loadTheme() {
    QSettings s("Engineering","PacketSniffer");
    QString t = s.value("Theme","Light").toString();
    g_dark = (t == "Dark");

    qApp->setStyle(QStyleFactory::create("Fusion"));
    QPalette p;
     if (t == "Light" || t == "Dark") {
        if (g_dark) {
            // === DARK ===
            p.setColor(QPalette::Window,          QColor(30,30,60));
            p.setColor(QPalette::WindowText,      QColor(210,210,230));
            p.setColor(QPalette::Base,            QColor(35,35,75));
            p.setColor(QPalette::AlternateBase,   QColor(45,45,95));
            p.setColor(QPalette::ToolTipBase,     QColor(210,210,230));
            p.setColor(QPalette::ToolTipText,     QColor(30,30,60));
            p.setColor(QPalette::Text,            QColor(230,230,250));
            p.setColor(QPalette::Button,          QColor(50,50,90));
            p.setColor(QPalette::ButtonText,      QColor(210,210,230));
            p.setColor(QPalette::Highlight,       QColor(70,130,180));
            p.setColor(QPalette::HighlightedText, Qt::white);
            p.setColor(QPalette::Link,            QColor(100,180,255));
        } else {
            // === LIGHT ===
            p.setColor(QPalette::Window,          QColor(245,245,255));
            p.setColor(QPalette::WindowText,      QColor(30,30,60));
            p.setColor(QPalette::Base,            QColor(255,255,255));
            p.setColor(QPalette::AlternateBase,   QColor(230,240,255));
            p.setColor(QPalette::ToolTipBase,     QColor(30,30,60));
            p.setColor(QPalette::ToolTipText,     QColor(245,245,255));
            p.setColor(QPalette::Text,            QColor(30,30,60));
            p.setColor(QPalette::Button,          QColor(225,235,255));
            p.setColor(QPalette::ButtonText,      QColor(30,30,60));
            p.setColor(QPalette::Highlight,       QColor(100,150,240));
            p.setColor(QPalette::HighlightedText, Qt::white);
            p.setColor(QPalette::Link,            QColor(0,102,204));
        }
        } else if (t == "Greenish") {
            p = buildGreenish();
        } else if (t == "Black+Orange") {
            p = buildBlackOrange();
        } else {
            p = loadPalette(QString("CustomThemes/%1").arg(t));
        }

    qApp->setPalette(p);
}

void toggleTheme() {
    QSettings s("Engineering","PacketSniffer");
    s.setValue("Theme", g_dark ? "Light" : "Dark");
    loadTheme();
}

QString toggleActionText() {
    return g_dark ? QStringLiteral("Light Mode")
                  : QStringLiteral("Dark Mode");
}

bool isDarkMode() {
    return g_dark;
}

void applyTheme(const QString &name) {
    QSettings s("Engineering","PacketSniffer");
    qApp->setStyle(QStyleFactory::create("Fusion"));

    if (name == "Light" || name == "Dark") {
        s.setValue("Theme", name);
        loadTheme();
        return;
    }

    QPalette p;
    if (name == "Greenish")         p = buildGreenish();
    else if (name == "Black+Orange")p = buildBlackOrange();
    else                            p = loadPalette(QString("CustomThemes/%1").arg(name));

    qApp->setPalette(p);
    s.setValue("Theme", name);
}

QPalette paletteForName(const QString &name) {
    if (name == "Light" || name == "Dark") {
        QSettings s("Engineering","PacketSniffer");
        QString old = s.value("Theme").toString();
        s.setValue("Theme", name);
        loadTheme();
        QPalette p = qApp->palette();
        s.setValue("Theme", old);
        loadTheme();
        return p;
    }
    if (name == "Greenish")         return buildGreenish();
    if (name == "Black+Orange")     return buildBlackOrange();
    return loadPalette(QString("CustomThemes/%1").arg(name));
}

void saveCustomPalette(const QString &name,
                       const QColor &window,
                       const QColor &bg,
                       const QColor &text,
                       const QColor &button,
                       const QColor &buttonText)
{
    QJsonObject o;
    o["Window"]     = window.name();
    o["Base"]     = bg.name();
    o["Text"]       = text.name();
    o["Button"]     = button.name();
    o["ButtonText"] = buttonText.name();
    QSettings s("Engineering","PacketSniffer");
    s.setValue(QString("CustomThemes/%1").arg(name),
               QJsonDocument(o).toJson(QJsonDocument::Compact));
}

QColor barColor() {
    return qApp->palette().color(QPalette::Text);
}

} // namespace Theme
