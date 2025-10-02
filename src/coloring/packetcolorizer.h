#ifndef PACKETCOLORIZER_H
#define PACKETCOLORIZER_H

#include <QVector>
#include <pcap.h>
#include <QColor>
#include <QRegularExpression>
#include <QString>
#include <QSettings>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include "coloringrule.h"

class PacketColorizer {
public:
    PacketColorizer();
    ~PacketColorizer();

    void addRule(ColoringRule&& rule);
    void clearRules();
    QColor colorFor(const pcap_pkthdr* hdr, const u_char* pkt) const;

    void saveRulesToSettings();
    void loadRulesFromSettings();

    bool saveRulesToJson(const QString &filePath);
    bool loadRulesFromJson(const QString &filePath);

    QVector<ColoringRule> rules() const { return m_rules; }

private:
    QVector<ColoringRule> m_rules;
    pcap_t*               m_dummyHandle;
    bpf_u_int32           m_dummyNetmask;
};

#endif // PACKETCOLORIZER_H