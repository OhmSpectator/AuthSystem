#-------------------------------------------------
#
# Project created by QtCreator 2012-03-30T13:45:37
#
#-------------------------------------------------

QT       += core gui

TARGET = GUI
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    Client.cpp \
    viewer.cpp

HEADERS  += mainwindow.h \
    Client.h \
    NetTypes.h \
    viewer.h

FORMS    += mainwindow.ui

LIBS += -lpolarssl
