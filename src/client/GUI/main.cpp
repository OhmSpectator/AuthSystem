#include <QtGui/QApplication>
#include "mainwindow.h"
#include "Client.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Client client;
    MainWindow w;
    client.setViewerController(&w);
    w.show();
    
    return a.exec();
}
