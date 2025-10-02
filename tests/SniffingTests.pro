QT += core testlib
CONFIG += console c++17
TEMPLATE = app
TARGET = SniffingTests

SOURCES += ../packets/sniffing.cpp \
           tst_sniffing.cpp
           

HEADERS += tst_sniffing.h

INCLUDEPATH += .. \
               ../protocols \
               ../packets \
               ../src \
               ../devices \
               ../filter

LIBS += -lpcap
