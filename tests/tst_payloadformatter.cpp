#include "tst_payloadformatter.h"

#include <QTest>

#include "../src/gui/payloadformatter.h"

void PayloadFormatterTest::asciiConversionHandlesBinary()
{
    QByteArray data;
    data.append(char(0x00));
    data.append(char(0x1F));
    data.append("Test");
    data.append(char(0x7F));
    data.append(char(0x80));

    const QString converted = PayloadFormatter::toAscii(data);
    QCOMPARE(converted, QString("..Test.."));
}

void PayloadFormatterTest::asciiConversionPreservesWhitespace()
{
    QByteArray data;
    data.append("Line1\nLine2\tEnd");

    const QString converted = PayloadFormatter::toAscii(data);
    QCOMPARE(converted, QString::fromLatin1("Line1\nLine2\tEnd"));
}

void PayloadFormatterTest::hexConversionProducesUppercase()
{
    const QByteArray data = QByteArray::fromHex("0a0b0c7f");
    const QString hex = PayloadFormatter::toHex(data);
    QCOMPARE(hex, QStringLiteral("0A 0B 0C 7F"));
}

void PayloadFormatterTest::formatSwitchesModes()
{
    const QByteArray data("Hi\x00");
    QCOMPARE(PayloadFormatter::format(data, PayloadFormatter::Mode::Ascii), QStringLiteral("Hi."));
    QCOMPARE(PayloadFormatter::format(data, PayloadFormatter::Mode::Hex), QStringLiteral("48 69 00"));
}
