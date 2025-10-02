#ifndef THEME_H
#define THEME_H

#include <QString>
#include <QPalette>
#include <QColor>
#include <QSettings>
#include <QInputDialog>
#include <QColorDialog>
#include <QApplication>
#include <QStyleFactory>
#include <QJsonDocument>
#include <QJsonObject>


namespace Theme {

    void loadTheme();
    void toggleTheme();         // going either way from light/dark to dark/light and saves it in config
    QString toggleActionText(); // RETURNS DARK/LIGHT MOE
    bool isDarkMode();

    void applyTheme(const QString &name);
    QPalette paletteForName(const QString &name);

    void saveCustomPalette(const QString &name,
                        const QColor &window,
                        const QColor &bg,
                        const QColor &text,
                        const QColor &button,
                        const QColor &buttonText);
                
    QColor barColor();
} 

#endif // THEME_H
