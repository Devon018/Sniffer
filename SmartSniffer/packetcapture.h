#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QObject>
#include <QThread>
#include <pcap.h>

class PacketCapture : public QThread
{
    Q_OBJECT
public:
    explicit PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();

    void setDeviceName(const QString &deviceName);
    void stopCapture();

signals:
    void packetCaptured(const QString &packetInfo);

protected:
    void run() override;

private:
    pcap_t *m_pcapHandle;
    QString m_deviceName;
    bool m_stop;
};

#endif // PACKETCAPTURE_H
