#-------------------------------------------------
#
# Project created by QtCreator 2015-01-02T22:01:32
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Read_pcap_file
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    ReadPcapFile.cpp

HEADERS  += mainwindow.h \
    ReadPcapFile.h

FORMS    += mainwindow.ui

linux-g++ { # For Linux
    LIBS += \
       -lpcap\
       -lboost_system\
}
