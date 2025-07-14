#ifndef CONFIGDATA_H
#define CONFIGDATA_H

#include <QMainWindow>
#include <QString>

struct ConfigData {
    QString device;
    QString filter;
};
Q_DECLARE_METATYPE(ConfigData)

#endif // CONFIGDATA_H
