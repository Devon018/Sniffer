#ifndef PACKETDATA_H
#define PACKETDATA_H

#include <QJsonObject>
#include <QJsonDocument>

class PacketData
{
public:
    QJsonObject data;

    PacketData();
    bool insert(const QString key, const QString value);
    QByteArray toJson();
};

#endif // PACKETDATA_H
