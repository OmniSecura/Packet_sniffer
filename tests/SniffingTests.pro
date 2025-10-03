QT += core testlib
CONFIG += console c++17
TEMPLATE = app
TARGET = SniffingTests

SOURCES += ../packets/sniffing.cpp \
           ../src/appsettings.cpp \
           ../src/gui/payloadformatter.cpp \
           tst_sniffing.cpp \
           tst_appsettings.cpp \
           tst_payloadformatter.cpp \
           test_main.cpp


HEADERS += tst_sniffing.h \
           tst_appsettings.h \
           tst_payloadformatter.h

INCLUDEPATH += .. \
               ../protocols \
               ../packets \
               ../src \
               ../devices \
               ../filter

LIBS += -lpcap