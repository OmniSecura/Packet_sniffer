QT += core gui widgets svg svgwidgets xml concurrent

TARGET = PacketSniffer
TEMPLATE = app

SOURCES += \
    devices/devices.cpp \
    filter/filter.cpp \
    packets/sniffing.cpp \
    packets/packet_geolocation/geolocation.cpp \
    packets/packet_geolocation/GeoMap.cpp \
    src/main.cpp \
    src/mainwindow.cpp \
    src/packetworker.cpp \
    src/coloring/packetcolorizer.cpp \
    src/coloring/customizerdialog.cpp \
    src/theme/theme.cpp \
    src/theme/otherthemesdialog.cpp \
    src/gui/mainwindow_ui.cpp \
    src/gui/mainwindow_sniffing.cpp \
    src/gui/mainwindow_packets.cpp \
    src/gui/selectionannotationdialog.cpp \
    src/gui/preferencesdialog.cpp \
    src/statistics/geooverviewdialog.cpp \
    src/statistics/statsdialog.cpp \
    src/statistics/sessionmanagerdialog.cpp \
    src/statistics/sessionstorage.cpp \
    src/statistics/charts/barChart.cpp \
    src/statistics/charts/lineChart.cpp \
    src/statistics/charts/pieChart.cpp \
    src/statistics/statistics.cpp \
    packets/packet_geolocation/CountryMapping/CountryMap.cpp \
    src/PacketTableModel.cpp \
    src/appsettings.cpp

HEADERS += \
    devices/devices.h \
    filter/filter.h \
    packets/sniffing.h \
    packets/packet_geolocation/geolocation.h \
    protocols/proto_struct.h \
    src/mainwindow.h \
    src/packetworker.h \
    src/coloring/packetcolorizer.h \
    src/coloring/customizerdialog.h \
    src/coloring/coloringrule.h \
    packets/packethelpers.h \
    src/theme/theme.h \
    src/theme/otherthemesdialog.h \
    src/gui/mainwindow_ui.h \
    src/gui/mainwindow_sniffing.h \
    src/gui/mainwindow_packets.h \
    src/gui/selectionannotationdialog.h \
    src/gui/preferencesdialog.h \
    src/statistics/geooverviewdialog.h \
    src/theme/ui_otherthemesdialog.h \
    src/statistics/statsdialog.h \
    src/statistics/sessionmanagerdialog.h \
    src/statistics/sessionstorage.h \
    src/statistics/charts/barChart.h \
    src/statistics/charts/lineChart.h \
    src/statistics/charts/pieChart.h \
    src/statistics/statistics.h \
    src/statistics/charts/ChartConfig.h \
    packets/packet_geolocation/GeoMap.h \
    packets/packet_geolocation/CountryMapping/CountryMap.h \
    src/PacketTableModel.h \
    src/appsettings.h

INCLUDEPATH += protocols

LIBS += -lpcap
LIBS += -lmaxminddb

CONFIG += c++17
