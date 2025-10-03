#ifndef TST_PAYLOADFORMATTER_H
#define TST_PAYLOADFORMATTER_H

#include <QObject>

class PayloadFormatterTest : public QObject
{
    Q_OBJECT
private slots:
    void asciiConversionHandlesBinary();
    void asciiConversionPreservesWhitespace();
    void hexConversionProducesUppercase();
    void formatSwitchesModes();
};

#endif // TST_PAYLOADFORMATTER_H
