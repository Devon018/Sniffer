#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QObject>
#include <QAtomicInteger>
#include <pcap.h>

class PacketCapture : public QThread
{
    Q_OBJECT
public:
    explicit PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();

    void setDeviceName(const QString &deviceName);
    void stopCapture();

    void setFilterRule(const QString &filterRule);

signals:
    void packetCaptured(const QString &packetInfo);

protected:
    void run() override;

private:
    pcap_t *m_pcapHandle = nullptr;
    QString m_deviceName;
    QAtomicInteger<bool> m_stop{false};
    QAtomicInteger<unsigned long long> m_packetCount{0};
};

#endif // PACKETCAPTURE_H
