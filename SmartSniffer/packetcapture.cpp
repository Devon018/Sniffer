#include "packetcapture.h"
#include <QDebug>
#include <pcap.h>

PacketCapture::PacketCapture(QObject *parent)
    : QThread(parent), m_pcapHandle(nullptr), m_stop(false)
{
}

PacketCapture::~PacketCapture()
{
    stopCapture();
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
    }
}

void PacketCapture::setDeviceName(const QString &deviceName)
{
    m_deviceName = deviceName;
}

void PacketCapture::stopCapture()
{
    m_stop = true;
}

void PacketCapture::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    m_pcapHandle = pcap_open(m_deviceName.toUtf8().constData(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf);
    if (!m_pcapHandle) {
        qWarning() << "pcap_open failed:" << errbuf;
        return;
    }

    // 设置过滤规则（可选），例如只捕获TCP包
    struct bpf_program fp;
    if (pcap_compile(m_pcapHandle, &fp, "tcp", 0, 0) == -1) {
        qWarning() << "Error compiling filter: " << pcap_geterr(m_pcapHandle);
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
        return;
    }
    if (pcap_setfilter(m_pcapHandle, &fp) == -1) {
        qWarning() << "Error setting filter: " << pcap_geterr(m_pcapHandle);
        pcap_freecode(&fp);
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
        return;
    }
    pcap_freecode(&fp);

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    while (!m_stop) {
        res = pcap_next_ex(m_pcapHandle, &header, &packet);
        if (res == 0) {
            // 超时，继续
            continue;
        } else if (res < 0) {
            qWarning() << "Error reading packet:" << pcap_geterr(m_pcapHandle);
            break;
        }

        // 简单处理：将包长度和当前时间作为信息发出
        QString info = QString("Packet length: %1, Time: %2.%3")
                           .arg(header->len)
                           .arg(header->ts.tv_sec)
                           .arg(header->ts.tv_usec);
        emit packetCaptured(info);
    }

    pcap_close(m_pcapHandle);
    m_pcapHandle = nullptr;
}
