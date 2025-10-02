#ifndef MAINWINDOW_SNIFFING_H
#define MAINWINDOW_SNIFFING_H

#include "../mainwindow.h"

void startSniffing();
void stopSniffing();
void handlePacket(const QByteArray &raw, const QStringList &infos, int datalinkType);

#endif //MAINWINDOW_SNIFFING_H