#include "packetdata.h"

PacketData::PacketData() {}

bool PacketData::insert(const QString key, const QString value)
{
    bool success = false;
    if (key == "source_port")
        data.insert(key, value.toInt()), success = true;
    if (key == "destination_port")
        data.insert(key, value.toInt()), success = true;
    if (key == "protocol")
        data.insert(key, value), success = true;
    if (key == "Total Fwd Packets")
        data.insert(key, value.toLongLong()), success = true;
    if (key == "Fwd Packet Length Mean")
        data.insert(key, value.toDouble()), success = true;
    if (key == "Flow IAT Mean")
        data.insert(key, value.toDouble()), success = true;
    if (key == "timestamp" || key == "source_ip" || key == "source_ip")
        data.insert(key, value), success = true;
    return success;
}

QByteArray PacketData::toJson()
{
    QJsonDocument doc(data);
    return doc.toJson(QJsonDocument::Compact);
}
