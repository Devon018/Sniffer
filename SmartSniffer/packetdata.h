#ifndef PACKETDATA_H
#define PACKETDATA_H

#include <QJsonObject>
#include <QJsonDocument>

class PacketData
{
private:
    QJsonObject data;
public:
    PacketData();
    bool insert(QString &key, QString &value);
    QString toJson();
};

#endif // PACKETDATA_H
