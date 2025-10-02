QT += core gui widgets testlib
CONFIG += console c++17
TEMPLATE = app
TARGET = SniffingTests

SOURCES += ../packets/sniffing.cpp \
           ../src/appsettings.cpp \
           ../src/statistics/statistics.cpp \
           ../src/statistics/sessionmanagerdialog.cpp \
           ../src/statistics/sessionstorage.cpp \
           tst_sniffing.cpp \
           tst_appsettings.cpp \
           tst_sessionmanager.cpp
           

HEADERS += tst_sniffing.h

INCLUDEPATH += .. \
               ../protocols \
               ../packets \
               ../src \
               ../devices \
               ../filter

LIBS += -lpcap
