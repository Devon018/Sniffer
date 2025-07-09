#include "packetcapture.h"
#include <QDateTime>
#include <pcap.h>

#include <WinSock2.h>
#include <ws2tcpip.h>
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
    m_stop.storeRelaxed(0);
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

void PacketCapture::startCapture()
{
    run();
}

void PacketCapture::stopCapture()
{
    m_stop.storeRelaxed(1);
}

void PacketCapture::setFilterRule(const QString &filterRule)
{
    m_filterRule = filterRule;
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
    if (!m_filterRule.isEmpty()) {
        struct bpf_program fp;
        if (pcap_compile(m_pcapHandle, &fp, m_filterRule.toUtf8().constData(), 0, 0) == -1) {
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
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    /*循环捕获package*/
    while (!m_stop.loadRelaxed()) {
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
#ifdef _WIN32
            const ip_header* ipHdr = reinterpret_cast<const ip_header*>(packet + sizeof(ether_header));
#else
            const struct ip* ipHdr = reinterpret_cast<const struct ip*>(packet + sizeof(ether_header));
#endif
            char srcIP[INET_ADDRSTRLEN];
            char dstIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipHdr->ip_src), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHdr->ip_dst), dstIP, INET_ADDRSTRLEN);

            QString info = QString("%1 > %2").arg(srcIP).arg(dstIP);

            // 解析传输层协议
            if (ipHdr->ip_proto == IPPROTO_TCP) {
                protocol = "TCP";

                // 计算 TCP 头位置（考虑 IP 头长度）
                const tcp_header* tcp_hdr = reinterpret_cast<const tcp_header*>(
                    packet + sizeof(ether_header) + (ipHdr->ip_hl * 4)  // ip_hl 是 32-bit words
                    );

                // 解析 TCP 标志位
                QString tcpFlags;
#ifdef _WIN32
                if (tcp_hdr->th_flags & TH_SYN) tcpFlags += "SYN ";
                if (tcp_hdr->th_flags & TH_ACK) tcpFlags += "ACK ";
                if (tcp_hdr->th_flags & TH_FIN) tcpFlags += "FIN ";
                if (tcp_hdr->th_flags & TH_RST) tcpFlags += "RST ";
#else
                if (tcp_hdr->th_flags & TH_SYN) tcpFlags += "SYN ";
                if (tcp_hdr->th_flags & TH_ACK) tcpFlags += "ACK ";
                if (tcp_hdr->th_flags & TH_FIN) tcpFlags += "FIN ";
                if (tcp_hdr->th_flags & TH_RST) tcpFlags += "RST ";
#endif

                // 格式化时间戳（秒.微秒）
                QString timestamp = QString("%1.%2")
                                        .arg(header->ts.tv_sec)
                                        .arg(header->ts.tv_usec, 6, 10, QLatin1Char('0'));

                // 构造显示信息
                QString info = QString("[%1] %2 → %3 %4 Len=%5 Time=%6 Flags=%7")
                                   .arg(++m_packetCount, 6, 10, QLatin1Char(' '))  // 6位宽序号
                                   .arg(srcAddr)
                                   .arg(dstAddr)
                                   .arg(protocol)
                                   .arg(header->len)
                                   .arg(timestamp)
                                   .arg(tcpFlags.trimmed());

                emit packetCaptured(info);
            }
            else if (ipHdr->ip_proto == IPPROTO_UDP) {
                protocol = "UDP";
                // UDP 处理类似
                // 计算 UDP 头位置
                const udp_header* udp_hdr = reinterpret_cast<const udp_header*>(
                    packet + sizeof(ether_header) + (ipHdr->ip_hl * 4)
                    );

                // 获取端口（注意字节序转换）
                uint16_t srcPort = ntohs(udp_hdr->uh_sport);
                uint16_t dstPort = ntohs(udp_hdr->uh_dport);
                uint16_t udpLen = ntohs(udp_hdr->uh_ulen);

                // 计算载荷长度（UDP长度 - 头长度）
                uint16_t payloadLen = udpLen - sizeof(udp_header);

                // 构造显示信息
                QString info = QString("[%1] %2:%3 → %4:%5 %6 Len=%7 (Payload=%8) Time=%9.%10")
                                   .arg(++m_packetCount, 6, 10, QLatin1Char(' '))  // 包序号
                                   .arg(srcAddr)                                  // 源IP
                                   .arg(srcPort)                                  // 源端口
                                   .arg(dstAddr)                                  // 目标IP
                                   .arg(dstPort)                                  // 目标端口
                                   .arg(protocol)                                 // 协议
                                   .arg(header->len)                              // 总长度
                                   .arg(payloadLen)                               // 载荷长度
                                   .arg(header->ts.tv_sec)                        // 秒
                                   .arg(header->ts.tv_usec, 6, 10, QLatin1Char('0')); // 微秒

                // 特殊协议识别
                if (dstPort == 53 || srcPort == 53) {
                    info += " [DNS]";
                } else if (dstPort == 67 || dstPort == 68 || srcPort == 67 || srcPort == 68) {
                    info += " [DHCP]";
                }

                emit packetCaptured(info);
            }
        }
        //如果是ipv6包
        else if (eth_type == ETHERTYPE_IPV6) {
            protocol = "IPv6";

            // 基本长度检查
            if (header->len < sizeof(ether_header) + sizeof(ip6_hdr)) {
                qWarning() << "Invalid IPv6 packet length";
                return;
            }

            const ip6_hdr* ipv6_hdr = reinterpret_cast<const ip6_hdr*>(
                packet + sizeof(ether_header)
                );

            // 转换IPv6地址为字符串
            char src_ip_str[INET6_ADDRSTRLEN];
            char dst_ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ipv6_hdr->ip6_src, src_ip_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ipv6_hdr->ip6_dst, dst_ip_str, INET6_ADDRSTRLEN);

            QString srcAddr = QString::fromUtf8(src_ip_str);
            QString dstAddr = QString::fromUtf8(dst_ip_str);

            // 解析扩展头和上层协议
            uint8_t next_header = ipv6_hdr->ip6_nxt;
            uint16_t payload_len = ntohs(ipv6_hdr->ip6_plen);
            size_t header_offset = sizeof(ip6_hdr);

            // 处理扩展头（最多处理3层扩展头）
            for (int i = 0; i < 3 && isExtensionHeader(next_header); ++i) {
                if (header->len < sizeof(ether_header) + header_offset + 1) {
                    break;
                }

                const uint8_t* ext_header = packet + sizeof(ether_header) + header_offset;
                uint8_t ext_len = (ext_header[1] + 1) * 8;  // 扩展头长度单位是8字节

                if (header->len < sizeof(ether_header) + header_offset + ext_len) {
                    break;
                }

                next_header = ext_header[0];
                header_offset += ext_len;
            }

            // 识别上层协议
            QString upperProtocol;
            switch (next_header) {
            case IPPROTO_TCP:  upperProtocol = "TCP"; break;
            case IPPROTO_UDP:  upperProtocol = "UDP"; break;
            case IPPROTO_ICMPV6: upperProtocol = "ICMPv6"; break;
            default: upperProtocol = QString("Proto=%1").arg(next_header);
            }

            // 构造显示信息
            QString info = QString("[%1] %2 → %3 %4 Len=%5 Payload=%6 Next=%7 Time=%8.%9")
                               .arg(++m_packetCount, 6, 10, QLatin1Char(' '))  // 包序号
                               .arg(srcAddr)                                  // 源IPv6
                               .arg(dstAddr)                                  // 目标IPv6
                               .arg(protocol)                                 // IPv6
                               .arg(header->len)                              // 总长度
                               .arg(payload_len)                              // 载荷长度
                               .arg(upperProtocol)                            // 上层协议
                               .arg(header->ts.tv_sec)                        // 秒
                               .arg(header->ts.tv_usec, 6, 10, QLatin1Char('0')); // 微秒

            emit packetCaptured(info);
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
