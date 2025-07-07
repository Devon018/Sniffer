#include "packetcapture.h"
#include <QDateTime>
#include <pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>

// Define ether_header and Ethernet type constants for Windows
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

struct ether_header {
    u_char  ether_dhost[ETHER_ADDR_LEN]; // Destination host address
    u_char  ether_shost[ETHER_ADDR_LEN]; // Source host address
    u_short ether_type;                  // IP? ARP? RARP? etc
};

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

PacketCapture::PacketCapture(QObject *parent)
    : QThread(parent), m_pcapHandle(nullptr), m_stop(false)
{
    m_stop.store(false);
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
    m_stop.store(true);
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

    /*循环捕获package*/
    while (!m_stop) {
        res = pcap_next_ex(m_pcapHandle, &header, &packet);
        if (res == 0) {
            continue; // 超时，继续等待
        } else if (res < 0) {
            qWarning() << "Error reading packet:" << pcap_geterr(m_pcapHandle);
            break;
        }

        // 解析 Ethernet 头部（假设是 Ethernet 帧）
        const struct ether_header* eth_hdr = reinterpret_cast<const ether_header*>(packet);
        uint16_t eth_type = ntohs(eth_hdr->ether_type);

        QString protocol = "Unknown";
        QString srcAddr, dstAddr;

        // 如果是 IPv4 包
        if (eth_type == ETHERTYPE_IP) {
            const struct ip* ip_hdr = reinterpret_cast<const ip*>(packet + sizeof(ether_header));
            srcAddr = QString::fromUtf8(inet_ntoa(ip_hdr->ip_src));
            dstAddr = QString::fromUtf8(inet_ntoa(ip_hdr->ip_dst));

            // 解析传输层协议
            if (ip_hdr->ip_p == IPPROTO_TCP) {
                protocol = "TCP";
                const struct tcphdr* tcp_hdr = reinterpret_cast<const tcphdr*>(
                    packet + sizeof(ether_header) + (ip_hdr->ip_hl << 2)
                );
                QString tcpFlags;
                if (tcp_hdr->th_flags & TH_SYN) tcpFlags += "SYN ";
                if (tcp_hdr->th_flags & TH_ACK) tcpFlags += "ACK ";
                if (tcp_hdr->th_flags & TH_FIN) tcpFlags += "FIN ";
                if (tcp_hdr->th_flags & TH_RST) tcpFlags += "RST ";

                QString info = QString("[%1] %2 → %3 %4 Len=%5 Time=%6.%7 Flags=%8")
                    .arg(++m_packetCount)                  // 包序号
                    .arg(srcAddr)                        // 源IP
                    .arg(dstAddr)                        // 目标IP
                    .arg(protocol)                       // 协议
                    .arg(header->len)                    // 包长度
                    .arg(header->ts.tv_sec)              // 时间戳秒
                    .arg(header->ts.tv_usec)             // 时间戳微秒
                    .arg(tcpFlags.trimmed());            // TCP标志位

                emit packetCaptured(info);
            }
            else if (ip_hdr->ip_p == IPPROTO_UDP) {
                protocol = "UDP";
                // UDP 处理类似
                const struct udphdr* udp_hdr = reinterpret_cast<const udphdr*>(
                    packet + sizeof(ether_header) + (ip_hdr->ip_hl << 2)
                );
                // UDP没有类似TCP的Flags，这里可以显示端口信息
                QString udpInfo = QString("SrcPort=%1 DstPort=%2")
                    .arg(ntohs(udp_hdr->uh_sport))
                    .arg(ntohs(udp_hdr->uh_dport));

                QString info = QString("[%1] %2 → %3 %4 Len=%5 Time=%6.%7 %8")
                    .arg(++m_packetCount)                  // 包序号
                    .arg(srcAddr)                        // 源IP
                    .arg(dstAddr)                        // 目标IP
                    .arg(protocol)                       // 协议
                    .arg(header->len)                    // 包长度
                    .arg(header->ts.tv_sec)              // 时间戳秒
                    .arg(header->ts.tv_usec)             // 时间戳微秒
                    .arg(udpInfo);                       // UDP端口信息

                emit packetCaptured(info);
            }
        }
        else if (eth_type == ETHERTYPE_IPV6) {
            protocol = "IPv6";
            if (header->len >= sizeof(ether_header) + sizeof(ip6_hdr)) {
                const struct ip6_hdr* ipv6_hdr = reinterpret_cast<const ip6_hdr*>(packet + sizeof(ether_header));

                char src_ip_str[INET6_ADDRSTRLEN];
                char dst_ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ipv6_hdr->ip6_src, src_ip_str, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &ipv6_hdr->ip6_dst, dst_ip_str, INET6_ADDRSTRLEN);
                srcAddr = QString::fromUtf8(src_ip_str);
                dstAddr = QString::fromUtf8(dst_ip_str);

                QString info = QString("[%1] %2 → %3 %4 Len=%5 Time=%6.%7")
                    .arg(++m_packetCount)                  // 包序号
                    .arg(srcAddr)                        // 源IP
                    .arg(dstAddr)                        // 目标IP
                    .arg(protocol)                       // 协议
                    .arg(header->len)                    // 包长度
                    .arg(header->ts.tv_sec)              // 时间戳秒
                    .arg(header->ts.tv_usec);             // 时间戳微秒
                emit packetCaptured(info);
            } else {
                qWarning() << "Invalid IPv6 packet length";
            }
        }
        else if (eth_type == ETHERTYPE_ARP) {
            protocol = "ARP";
            // ARP 处理
            // ARP 头部结构定义
            struct arp_header {
                uint16_t htype;
                uint16_t ptype;
                uint8_t hlen;
                uint8_t plen;
                uint16_t oper;
                uint8_t sha[6];
                uint8_t spa[4];
                uint8_t tha[6];
                uint8_t tpa[4];
            };

            if (header->len >= sizeof(ether_header) + sizeof(arp_header)) {
                const arp_header* arp = reinterpret_cast<const arp_header*>(packet + sizeof(ether_header));
                QString srcMac = QString("%1:%2:%3:%4:%5:%6")
                    .arg(QString::number(arp->sha[0], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->sha[1], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->sha[2], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->sha[3], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->sha[4], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->sha[5], 16).rightJustified(2, '0'));
                QString dstMac = QString("%1:%2:%3:%4:%5:%6")
                    .arg(QString::number(arp->tha[0], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->tha[1], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->tha[2], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->tha[3], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->tha[4], 16).rightJustified(2, '0'))
                    .arg(QString::number(arp->tha[5], 16).rightJustified(2, '0'));
                QString srcIp = QString("%1.%2.%3.%4")
                    .arg(arp->spa[0]).arg(arp->spa[1]).arg(arp->spa[2]).arg(arp->spa[3]);
                QString dstIp = QString("%1.%2.%3.%4")
                    .arg(arp->tpa[0]).arg(arp->tpa[1]).arg(arp->tpa[2]).arg(arp->tpa[3]);
                QString op;
                switch (ntohs(arp->oper)) {
                    case 1: op = "Request"; break;
                    case 2: op = "Reply"; break;
                    default: op = QString("Op%1").arg(ntohs(arp->oper));
                }
                QString info = QString("[%1] ARP %2 %3 (%4) → %5 (%6) Len=%7 Time=%8.%9")
                    .arg(++m_packetCount)
                    .arg(op)
                    .arg(srcIp)
                    .arg(srcMac)
                    .arg(dstIp)
                    .arg(dstMac)
                    .arg(header->len)
                    .arg(header->ts.tv_sec)
                    .arg(header->ts.tv_usec);
                emit packetCaptured(info);
            } else {
                qWarning() << "Invalid ARP packet length";
            }
        }

        // 默认情况下仍输出基本信息
        if (protocol == "Unknown") {
            QString info = QString("[%1] Unknown protocol (0x%2), Len=%3")
                .arg(++m_packetCount)
                .arg(eth_type, 0, 16)
                .arg(header->len);
            emit packetCaptured(info);
        }
    }

    pcap_close(m_pcapHandle);
    m_pcapHandle = nullptr;
}