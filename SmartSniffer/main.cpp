#include "mainwindow.h"

#include <QApplication>
#include <QLocale>
#include <QTranslator>
#include "configdata.h""

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    qRegisterMetaType<ConfigData>("ConfigData");

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "SmartSniffer_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            a.installTranslator(&translator);
            break;
        }
    }
    MainWindow w;
    w.show();
    return a.exec();
}
