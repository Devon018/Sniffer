#include "packetcapture.h"
#include <QDateTime>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>
#include <cstring>
#include <pcap.h>
#include "packetdata.h"

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
    onStopCapture();
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
    }
}

bool PacketCapture::isCapturing()
{
    return this->m_pcapHandle != NULL;
}

void PacketCapture::setDeviceName(const QString &deviceName)
{
    m_deviceName = deviceName;
}

void PacketCapture::setFilterRule(const QString &filterRule)
{
    m_filterRule = filterRule;
}

QString timestampToIso(const long &ts_sec) {
    QDateTime dt = QDateTime::fromSecsSinceEpoch(ts_sec, Qt::UTC);
    return dt.toString(Qt::ISODate);
}

QByteArray AIModelInputFormatter(quint16 srcPort, quint16 dstPort, const QString& protocol,
                                 const QVariantMap& statMap, const long& ts_sec,
                                 const QString& srcIP, const QString& dstIP)
{
    QJsonObject json;

    json["Average Packet Size"] = statMap.value("Average Packet Size").toDouble();
    json["Flow Bytes/s"] = statMap.value("Flow Bytes/s").toDouble();
    json["Max Packet Length"] = statMap.value("Max Packet Length").toInt();
    json["Fwd Packet Length Mean"] = statMap.value("Fwd Packet Length Mean").toDouble();
    json["Fwd IAT Min"] = statMap.value("Fwd IAT Min").toDouble();
    json["Total Length of Fwd Packets"] = statMap.value("Total Length of Fwd Packets").toInt();
    json["Flow IAT Mean"] = statMap.value("Flow IAT Mean").toDouble();
    json["Fwd Packet Length Max"] = statMap.value("Fwd Packet Length Max").toInt();
    json["Fwd IAT Std"] = statMap.value("Fwd IAT Std").toDouble();
    json["Fwd Header Length"] = statMap.value("Fwd Header Length").toInt();
    json["Total Fwd Packets"] = statMap.value("Total Fwd Packets").toInt();

    QDateTime timestamp = QDateTime::fromSecsSinceEpoch(ts_sec, Qt::UTC);
    json["timestamp"] = timestamp.toString(Qt::ISODate);
    json["source_ip"] = srcIP;
    json["source_port"] = srcPort;
    json["destination_ip"] = dstIP;
    json["destination_port"] = dstPort;
    json["protocol"] = protocol;

    return QJsonDocument(json).toJson(QJsonDocument::Compact);
}

// void PacketCapture::applyAIModel(const QString &srcIP, const QString &dstIP,
//                                     const QString &protocol, const long &ts_sec,
//                                     u_short &srcPort, u_short &dstPort,
//                                     std::function<void(const QString &)> callback)
// {
//     qDebug() << "Calling applyAIModel() with protocol " << protocol << " ...";
//     qDebug() << "m_networkManager:" << m_networkManager;
//     qDebug() << "m_networkManager thread:" << m_networkManager->thread();
//     qDebug() << "Current thread:" << QThread::currentThread();
//     QNetworkRequest request(QUrl("http://127.0.0.1:5000/predict"));
//     request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

//     QVariantMap statMap = getFlowStats(srcIP, dstIP);
//     qDebug() << "statMap gotten.";
//     QByteArray data = AIModelInputFormatter(srcPort, dstPort, protocol, statMap, ts_sec, srcIP, dstIP);
//     qDebug() << "Sending " << data.toStdString() << " to Model...";

//     QNetworkReply *reply = m_networkManager->post(request, data);

//     connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
//         if (reply->error() == QNetworkReply::NoError) {
//             QByteArray response = reply->readAll();
//             QJsonParseError parseError;
//             QJsonDocument doc = QJsonDocument::fromJson(response, &parseError);

//             if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
//                 QJsonObject obj = doc.object();
//                 QString category = obj.value("category").toString();
//                 qDebug() << "[AI Category]:" << category;
//                 callback(category);
//             } else {
//                 qWarning() << "[AI parse error]:" << parseError.errorString();
//                 callback("N/A");
//             }
//         } else {
//             qWarning() << "[AI error]:" << reply->errorString();
//             callback("N/A");
//         }
//         reply->deleteLater();
//     });
// }

QVariantMap PacketCapture::getFlowStats(const QString& srcAddr, const QString& dstAddr) const
{
    QString flowKey = srcAddr + "->" + dstAddr;
    const FlowStats& stats = flowStats[flowKey];
    QVariantMap statMap;

    double duration_sec = (stats.flowEndTime - stats.flowStartTime) / 1e6;
    double avgLen = stats.totalFwdPackets > 0 ? (double)stats.totalFwdLength / stats.totalFwdPackets : 0.0;
    double iatMean = stats.packetCount > 0 ? stats.totalIAT / (double)stats.packetCount / 1000.0 : 0.0;
    double iatStd = 0.0;

    if (stats.totalFwdPackets > 0) {
        double mean = avgLen;
        double meanSquares = (double)stats.fwdPacketLengthSumSquares / stats.totalFwdPackets;
        iatStd = sqrt(meanSquares - mean * mean);  // 简单标准差
    }

    statMap["Average Packet Size"] = avgLen;
    statMap["Flow Bytes/s"] = duration_sec > 0 ? (double)stats.totalFwdLength / duration_sec : 0.0;
    statMap["Max Packet Length"] = stats.maxPacketLength;
    statMap["Fwd Packet Length Mean"] = avgLen;
    statMap["Fwd IAT Min"] = stats.minIAT == std::numeric_limits<quint32>::max() ? 0 : stats.minIAT / 1000.0;
    statMap["Total Length of Fwd Packets"] = stats.totalFwdLength;
    statMap["Flow IAT Mean"] = iatMean;
    statMap["Fwd Packet Length Max"] = stats.fwdPacketLengthMax;
    statMap["Fwd IAT Std"] = iatStd;
    statMap["Fwd Header Length"] = stats.fwdHeaderLengthTotal;
    statMap["Total Fwd Packets"] = stats.totalFwdPackets;

    return statMap;
}

void PacketCapture::onStartCapture()
{
    qDebug() << "开始抓包，接口:" << this->m_deviceName << ", 过滤规则:" << this->m_filterRule;

    m_stop.storeRelaxed(0);

    this->start();
}

void PacketCapture::onStopCapture()
{
    m_stop.storeRelaxed(1);
}

void PacketCapture::onConfigChanged(const ConfigData &config)
{
    this->setDeviceName(config.device);
    this->setFilterRule(config.filter);
    qDebug() << "Device set: " << this->m_deviceName << "; Filter set: " << this->m_filterRule;
}

void PacketCapture::updateFlowStats(const QString& srcAddr, const QString& dstAddr,
                                    quint32 packetLen, const timeval& timestamp,
                                    quint32 headerLen)
{
    QString flowKey = srcAddr + "->" + dstAddr;
    qint64 currentTime = timestamp.tv_sec * 1000000LL + timestamp.tv_usec;

    FlowStats& stats = flowStats[flowKey];

    if (stats.flowStartTime == 0)
        stats.flowStartTime = currentTime;
    stats.flowEndTime = currentTime;

    stats.totalFwdPackets++;
    stats.totalFwdLength += packetLen;
    stats.fwdHeaderLengthTotal += headerLen;

    if (packetLen > stats.fwdPacketLengthMax)
        stats.fwdPacketLengthMax = packetLen;
    if (packetLen > stats.maxPacketLength)
        stats.maxPacketLength = packetLen;

    stats.fwdPacketLengthSumSquares += packetLen * packetLen;

    if (stats.lastPacketTime > 0) {
        qint64 iat = currentTime - stats.lastPacketTime;
        stats.totalIAT += iat;
        stats.packetCount++;

        if (iat < stats.minIAT)
            stats.minIAT = iat;
    }

    stats.lastPacketTime = currentTime;
}

QString PacketCapture::extractPayload(const u_char* packet, const struct pcap_pkthdr* header) {
    QString payload;

    if (header->caplen < sizeof(ether_header)) {
        return payload;  // 不够 Ethernet 头长度
    }

    // 获取以太网头
    const ether_header* eth_hdr = reinterpret_cast<const ether_header*>(packet);
    uint16_t etherType = ntohs(eth_hdr->ether_type);

    const u_char* data = packet + sizeof(ether_header);
    int remaining = header->caplen - sizeof(ether_header);

    if (etherType == 0x0800) {
        // IPv4
        if (remaining < sizeof(ip_header)) return payload;

        const ip_header* ip_hdr = reinterpret_cast<const ip_header*>(data);
        int ip_header_len = (ip_hdr->ip_hl) * 4;

        if (remaining < ip_header_len) return payload;

        data += ip_header_len;
        remaining -= ip_header_len;

        if (ip_hdr->ip_proto == IPPROTO_TCP) {
            if (remaining < sizeof(tcp_header)) return payload;
            const tcp_header* tcp_hdr = reinterpret_cast<const tcp_header*>(data);
            int tcp_header_len = (tcp_hdr->th_offx2 >> 4) * 4;

            if (remaining < tcp_header_len) return payload;

            const u_char* payload_start = data + tcp_header_len;
            int payload_len = remaining - tcp_header_len;

            if (payload_len > 0) {
                QByteArray payloadBytes(reinterpret_cast<const char*>(payload_start), payload_len);
                payload = QString::fromUtf8(payloadBytes);

                // HTTP body 提取
                if (payload.startsWith("GET ") || payload.startsWith("POST") ||
                    payload.startsWith("HEAD") || payload.startsWith("PUT ") ||
                    payload.startsWith("DELETE") || payload.startsWith("OPTIONS") ||
                    payload.startsWith("HTTP/")) {
                    int body_start = payload.indexOf("\r\n\r\n");
                    if (body_start != -1) {
                        body_start += 4;
                        payload = payload.mid(body_start);
                    }
                }
            }
        }
        else if (ip_hdr->ip_proto == IPPROTO_UDP) {
            if (remaining < sizeof(udp_header)) return payload;
            const udp_header* udp_hdr = reinterpret_cast<const udp_header*>(data);
            int udp_header_len = 8;

            const u_char* payload_start = data + udp_header_len;
            int payload_len = ntohs(udp_hdr->uh_ulen) - udp_header_len;

            if (payload_len > 0 && payload_len <= (remaining - udp_header_len)) {
                QByteArray payloadBytes(reinterpret_cast<const char*>(payload_start), payload_len);
                payload = QString::fromUtf8(payloadBytes);
            }
        }
        // else 可以添加 ICMP 等协议支持
    }
    else if (etherType == 0x86DD) {
        // IPv6
        if (remaining < sizeof(ip6_hdr)) return payload;

        const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(data);
        data += sizeof(ip6_hdr);
        remaining -= sizeof(ip6_hdr);

        if (ip6->ip6_nxt == IPPROTO_TCP) {
            if (remaining < sizeof(tcp_header)) return payload;
            const tcp_header* tcp_hdr = reinterpret_cast<const tcp_header*>(data);
            int tcp_header_len = (tcp_hdr->th_offx2 >> 4) * 4;

            if (remaining < tcp_header_len) return payload;

            const u_char* payload_start = data + tcp_header_len;
            int payload_len = remaining - tcp_header_len;

            if (payload_len > 0) {
                QByteArray payloadBytes(reinterpret_cast<const char*>(payload_start), payload_len);
                payload = QString::fromUtf8(payloadBytes);
            }
        }
        else if (ip6->ip6_nxt == IPPROTO_UDP) {
            if (remaining < sizeof(udp_header)) return payload;
            const udp_header* udp_hdr = reinterpret_cast<const udp_header*>(data);
            int udp_header_len = 8;

            const u_char* payload_start = data + udp_header_len;
            int payload_len = ntohs(udp_hdr->uh_ulen) - udp_header_len;

            if (payload_len > 0 && payload_len <= (remaining - udp_header_len)) {
                QByteArray payloadBytes(reinterpret_cast<const char*>(payload_start), payload_len);
                payload = QString::fromUtf8(payloadBytes);
            }
        }
    }
    else if (etherType == 0x0806) {
        // ARP
        if (remaining < sizeof(arp_header)) return payload;

        const arp_header* arp = reinterpret_cast<const arp_header*>(data);
        QString sha = QString("%1:%2:%3:%4:%5:%6")
                          .arg(arp->sha[0], 2, 16, QLatin1Char('0'))
                          .arg(arp->sha[1], 2, 16, QLatin1Char('0'))
                          .arg(arp->sha[2], 2, 16, QLatin1Char('0'))
                          .arg(arp->sha[3], 2, 16, QLatin1Char('0'))
                          .arg(arp->sha[4], 2, 16, QLatin1Char('0'))
                          .arg(arp->sha[5], 2, 16, QLatin1Char('0'));
        QString spa = QString("%1.%2.%3.%4")
                          .arg(arp->spa[0])
                          .arg(arp->spa[1])
                          .arg(arp->spa[2])
                          .arg(arp->spa[3]);
        QString tha = QString("%1:%2:%3:%4:%5:%6")
                          .arg(arp->tha[0], 2, 16, QLatin1Char('0'))
                          .arg(arp->tha[1], 2, 16, QLatin1Char('0'))
                          .arg(arp->tha[2], 2, 16, QLatin1Char('0'))
                          .arg(arp->tha[3], 2, 16, QLatin1Char('0'))
                          .arg(arp->tha[4], 2, 16, QLatin1Char('0'))
                          .arg(arp->tha[5], 2, 16, QLatin1Char('0'));
        QString tpa = QString("%1.%2.%3.%4")
                          .arg(arp->tpa[0])
                          .arg(arp->tpa[1])
                          .arg(arp->tpa[2])
                          .arg(arp->tpa[3]);

        payload = QString("ARP: %1 (%2) → %3 (%4)")
                      .arg(spa, sha)
                      .arg(tpa, tha);
    }

    return payload;
}

const void* memmem(const void* haystack, size_t haystacklen,
                      const void* needle, size_t needlelen)
{
    if (needlelen == 0) return haystack;

    const uint8_t* h = static_cast<const uint8_t*>(haystack);
    const uint8_t* n = static_cast<const uint8_t*>(needle);

    for (size_t i = 0; i <= haystacklen - needlelen; ++i) {
        if (memcmp(h + i, n, needlelen) == 0) {
            return h + i;
        }
    }
    return nullptr;
}

void PacketCapture::run()
{
    qDebug() << "Calling PacketCapture::run()...\n" << m_deviceName << "\n";

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

    // 循环捕获packets
    while (!m_stop.loadRelaxed()) {
        res = pcap_next_ex(m_pcapHandle, &header, &packet);
        if (res == 0) {
            continue; // 超时，继续等待
        } else if (res < 0) {
            qWarning() << "Error reading packet:" << pcap_geterr(m_pcapHandle);
            break;
        }

        // 解析Ethernet头部（假设是Ethernet帧）
        const struct ether_header* eth_hdr = reinterpret_cast<const ether_header*>(packet);
        uint16_t eth_type = ntohs(eth_hdr->ether_type);

        QString protocol = "Unknown";
        QString srcAddr, dstAddr;
        QString httpBody = extractPayload(packet, header);
        QString hexData = httpBody.toUtf8().toHex(' ').toUpper();

        // IPv4
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

            srcAddr = QString("%1.%2.%3.%4")
                          .arg((ntohl(ipHdr->ip_src.s_addr) >> 24) & 0xFF)
                          .arg((ntohl(ipHdr->ip_src.s_addr) >> 16) & 0xFF)
                          .arg((ntohl(ipHdr->ip_src.s_addr) >> 8) & 0xFF)
                          .arg(ntohl(ipHdr->ip_src.s_addr) & 0xFF);

            dstAddr = QString("%1.%2.%3.%4")
                          .arg((ntohl(ipHdr->ip_dst.s_addr) >> 24) & 0xFF)
                          .arg((ntohl(ipHdr->ip_dst.s_addr) >> 16) & 0xFF)
                          .arg((ntohl(ipHdr->ip_dst.s_addr) >> 8) & 0xFF)
                          .arg(ntohl(ipHdr->ip_dst.s_addr) & 0xFF);

            QString info = QString("%1 > %2").arg(srcIP).arg(dstIP);

            qDebug() << "http body: " << httpBody;

            if (ipHdr->ip_proto == IPPROTO_TCP) {
                protocol = "TCP";

                // 安全解析IP头长度
                uint8_t ihl = ipHdr->ip_hl & 0x0F;
                size_t ipHeaderLen = ihl * 4;
                uint16_t totalLen = ntohs(ipHdr->ip_len);
                if (totalLen < ipHeaderLen) return;

                // 解析并格式化IP地址
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipHdr->ip_src, buf, sizeof(buf));
                srcAddr = QString::fromLatin1(buf);
                inet_ntop(AF_INET, &ipHdr->ip_dst, buf, sizeof(buf));
                dstAddr = QString::fromLatin1(buf);

                // 计算TCP头部位置与长度
                const u_char* tcpPtr = packet + sizeof(ether_header) + ipHeaderLen;
                struct tcp_header rawTcp;
                memcpy(&rawTcp, tcpPtr, sizeof(rawTcp));  // 防止对齐问题
                uint8_t thl = (rawTcp.th_offx2 >> 4) & 0x0F;
                size_t tcpHeaderLen = thl * 4;
                int headerLen = ipHeaderLen + tcpHeaderLen;
                if (totalLen < ipHeaderLen + tcpHeaderLen) return;

                size_t tcpDataOffset = sizeof(ether_header) + ipHeaderLen + tcpHeaderLen;
                size_t tcpDataLength = totalLen - ipHeaderLen - tcpHeaderLen;
                const u_char* tcpData = packet + tcpDataOffset;

                // HTTPS(TLS)检测
                bool isTls = false;
                QString tlsInfo;
                if (tcpDataLength >= 5 && tcpData[0] == 0x16 && tcpData[1] == 0x03 && tcpData[2] <= 0x04) {
                    uint16_t recLen;
                    memcpy(&recLen, tcpData + 3, sizeof(recLen));
                    recLen = ntohs(recLen);
                    if (recLen + 5 <= tcpDataLength) {
                        isTls = true;
                        protocol = "HTTPS";

                        // 仅处理ClientHello/ServerHello
                        if (tcpDataLength >= 6 && tcpData[5] == 0x01) {  // Client Hello
                            const u_char* pos = tcpData + 43;
                            if (pos < tcpData + tcpDataLength) {
                                // 跳过 SessionID
                                uint8_t sidLen = *pos++;
                                pos += sidLen;
                                // 跳过 CipherSuites
                                if (pos + 2 <= tcpData + tcpDataLength) {
                                    uint16_t csLen;
                                    memcpy(&csLen, pos, 2);
                                    csLen = ntohs(csLen);
                                    pos += 2 + csLen;
                                }
                                // 跳过 CompressionMethods
                                if (pos < tcpData + tcpDataLength) {
                                    uint8_t cmLen = *pos++;
                                    pos += cmLen;
                                }
                                // 解析扩展字段寻找 SNI
                                if (pos + 4 <= tcpData + tcpDataLength) {
                                    uint16_t extLen;
                                    memcpy(&extLen, pos, 2);
                                    extLen = ntohs(extLen);
                                    pos += 2;
                                    const u_char* extEnd = pos + extLen;
                                    while (pos + 4 <= extEnd) {
                                        uint16_t extType, extFieldLen;
                                        memcpy(&extType, pos, 2);
                                        memcpy(&extFieldLen, pos + 2, 2);
                                        extType = ntohs(extType);
                                        extFieldLen = ntohs(extFieldLen);
                                        if (extType == 0x0000 && pos + 4 + extFieldLen <= extEnd) {
                                            // SNI
                                            uint16_t nameListLen;
                                            memcpy(&nameListLen, pos + 4, 2);
                                            nameListLen = ntohs(nameListLen);
                                            const u_char* snPos = pos + 6;
                                            const u_char* snEnd = snPos + nameListLen;
                                            while (snPos + 3 <= snEnd) {
                                                uint8_t nameType = *snPos;
                                                uint16_t nameLen;
                                                memcpy(&nameLen, snPos + 1, 2);
                                                nameLen = ntohs(nameLen);
                                                if (nameType == 0x00 && snPos + 3 + nameLen <= snEnd) {
                                                    QString serverName = QString::fromUtf8(
                                                        reinterpret_cast<const char*>(snPos + 3), nameLen);
                                                    tlsInfo = QString("Client Hello (SNI: %1)").arg(serverName);
                                                    break;
                                                }
                                                snPos += 3 + nameLen;
                                            }
                                            break;
                                        }
                                        pos += 4 + extFieldLen;
                                    }
                                }
                            }
                            if (tlsInfo.isEmpty()) tlsInfo = "Client Hello";
                        }
                        else if (tcpDataLength >= 6 && tcpData[5] == 0x02) {
                            tlsInfo = "Server Hello";
                        }
                        else {
                            tlsInfo = "TLS Handshake";
                        }
                    }
                }

                QString timestamp = QString("%1.%2")
                                        .arg(header->ts.tv_sec)
                                        .arg(header->ts.tv_usec, 6, 10, QLatin1Char('0'));

                updateFlowStats(srcAddr, dstAddr, header->len, header->ts, headerLen);

                // HTTP 请求/响应检测
                if (!isTls) {
                    bool isHttpRequest = (tcpDataLength >= 4 && (
                                              memcmp(tcpData, "GET ", 4) == 0 ||
                                              memcmp(tcpData, "POST", 4) == 0 ||
                                              memcmp(tcpData, "HEAD", 4) == 0 ||
                                              memcmp(tcpData, "PUT ", 4) == 0 ||
                                              memcmp(tcpData, "DELETE", 6) == 0 ||
                                              memcmp(tcpData, "OPTIONS", 7) == 0));
                    bool isHttpResponse = (tcpDataLength >= 5 && memcmp(tcpData, "HTTP/", 5) == 0);

                    if (isHttpRequest || isHttpResponse) {
                        protocol = "HTTP";
                        const u_char* p = tcpData;
                        const u_char* end = tcpData + tcpDataLength - 3;
                        const u_char* endOfHeaders = nullptr;
                        while (p < end) {
                            if (p[0]=='\r' && p[1]=='\n' && p[2]=='\r' && p[3]=='\n') {
                                endOfHeaders = p + 4;
                                break;
                            }
                            ++p;
                        }
                        if (endOfHeaders) {
                            size_t headersLen = endOfHeaders - tcpData;
                            // 提取首行
                            const u_char* lineEnd = static_cast<const u_char*>(
                                memchr(tcpData, '\n', headersLen));
                            QString firstLine;
                            if (lineEnd) {
                                firstLine = QString::fromUtf8(
                                                reinterpret_cast<const char*>(tcpData),
                                                lineEnd - tcpData).trimmed();
                            }
                            // 提取 Host
                            QString host;
                            if (isHttpRequest) {
                                const u_char* hStart = static_cast<const u_char*>(
                                    memmem(tcpData, headersLen, "Host: ", 6));
                                if (hStart) {
                                    hStart += 6;
                                    const u_char* hEnd = static_cast<const u_char*>(
                                        memchr(hStart, '\n', headersLen - (hStart - tcpData)));
                                    if (hEnd) {
                                        host = QString::fromUtf8(
                                                   reinterpret_cast<const char*>(hStart),
                                                   hEnd - hStart).trimmed();
                                    }
                                }
                            }
                            QString httpInfo = host.isEmpty()
                                                   ? firstLine
                                                   : QString("%1 (%2)").arg(firstLine, host);

                            QString info = QString("[%1] %2:%3 → %4:%5 %6 Len=%7 Time=%8 HTTP: %9")
                                               .arg(++m_packetCount)
                                               .arg(srcAddr)
                                               .arg(ntohs(rawTcp.th_sport))
                                               .arg(dstAddr)
                                               .arg(ntohs(rawTcp.th_dport))
                                               .arg(protocol)
                                               .arg(header->len)
                                               .arg(timestamp)
                                               .arg(httpInfo);

                            QByteArray data = AIModelInputFormatter(rawTcp.th_sport, rawTcp.th_dport, protocol,
                                                                    getFlowStats(srcAddr, dstAddr), header->ts.tv_sec, srcAddr, dstAddr);
                            emit applyAIModel(data, m_packetCount);

                            int tmpCount = this->m_packetCount;
                            // applyAIModel(srcAddr, dstAddr, protocol, header->ts.tv_sec, rawTcp.th_sport, rawTcp.th_dport,
                            //             [tmpCount, this](const QString &category) {
                            //                 qDebug() << tmpCount << "的分类结果为: " << category;
                            //                 emit this->PacketCapture::categoryReceived(tmpCount, category);
                            //             });
                            emit packetCaptured(info, httpBody, hexData);
                        }
                    }
                }
                else {
                    // HTTPS 显示
                    QString info = QString("[%1] %2:%3 → %4:%5 %6 Len=%7 Time=%8 TLS: %9")
                                       .arg(++m_packetCount)
                                       .arg(srcAddr)
                                       .arg(ntohs(rawTcp.th_sport))
                                       .arg(dstAddr)
                                       .arg(ntohs(rawTcp.th_dport))
                                       .arg(protocol)
                                       .arg(header->len)
                                       .arg(timestamp)
                                       .arg(tlsInfo);

                    QByteArray data = AIModelInputFormatter(rawTcp.th_sport, rawTcp.th_dport, protocol,
                                                            getFlowStats(srcAddr, dstAddr), header->ts.tv_sec, srcAddr, dstAddr);
                    emit applyAIModel(data, m_packetCount);

                    int tmpCount = this->m_packetCount;
                    // applyAIModel(srcAddr, dstAddr, protocol, header->ts.tv_sec, rawTcp.th_sport, rawTcp.th_dport,
                    //              [tmpCount, this](const QString &category) {
                    //                  qDebug() << tmpCount << "的分类结果为: " << category;
                    //                  emit this->PacketCapture::categoryReceived(tmpCount, category);
                    //              });
                    emit packetCaptured(info, httpBody, hexData);
                }

                // 不是 HTTP/HTTPS，显示 TCP Flags
                QString tcpFlags;
                if (rawTcp.th_flags & TH_SYN) tcpFlags += "SYN,";
                if (rawTcp.th_flags & TH_ACK) tcpFlags += "ACK,";
                if (rawTcp.th_flags & TH_FIN) tcpFlags += "FIN,";
                if (rawTcp.th_flags & TH_RST) tcpFlags += "RST,";
                tcpFlags.removeLast(); // 删去末尾的逗号

                QString info = QString("[%1] %2:%3 → %4:%5 %6 Len=%7 Time=%8 Flags=%9")
                                   .arg(++m_packetCount)
                                   .arg(srcAddr)
                                   .arg(ntohs(rawTcp.th_sport))
                                   .arg(dstAddr)
                                   .arg(ntohs(rawTcp.th_dport))
                                   .arg(protocol)
                                   .arg(header->len)
                                   .arg(timestamp)
                                   .arg(tcpFlags.trimmed());

                QByteArray data = AIModelInputFormatter(rawTcp.th_sport, rawTcp.th_dport, protocol,
                                                        getFlowStats(srcAddr, dstAddr), header->ts.tv_sec, srcAddr, dstAddr);
                emit applyAIModel(data, m_packetCount);

                // int tmpCount = this->m_packetCount;
                // applyAIModel(srcAddr, dstAddr, protocol, header->ts.tv_sec, rawTcp.th_sport, rawTcp.th_dport,
                //              [tmpCount, this](const QString &category) {
                //                  qDebug() << tmpCount << "的分类结果为: " << category;
                //                  emit this->PacketCapture::categoryReceived(tmpCount, category);
                //              });
                emit packetCaptured(info, httpBody, hexData);
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

                updateFlowStats(srcAddr, dstAddr, header->len, header->ts, sizeof(udp_header));

                // 构造显示信息
                QString info = QString("[%1] %2:%3 → %4:%5 %6 Len=%7 Time=%8.%9 Payload=%10")
                                   .arg(++m_packetCount)                          // 包序号
                                   .arg(srcAddr)                                  // 源IP
                                   .arg(srcPort)                                  // 源端口
                                   .arg(dstAddr)                                  // 目标IP
                                   .arg(dstPort)                                  // 目标端口
                                   .arg(protocol)                                 // 协议
                                   .arg(header->len)                              // 总长度
                                   .arg(header->ts.tv_sec)                        // 秒
                                   .arg(header->ts.tv_usec, 6, 10, QLatin1Char('0')) // 微秒
                                   .arg(payloadLen);                               // 载荷长度

                // 特殊协议识别
                if (dstPort == 53 || srcPort == 53) {
                    info += " [DNS]";
                } else if (dstPort == 67 || dstPort == 68 || srcPort == 67 || srcPort == 68) {
                    info += " [DHCP]";
                }

                qDebug() << m_packetCount << " UDP packet info formatted.";

                int tmpCount = this->m_packetCount;
                // applyAIModel(srcAddr, dstAddr, protocol, header->ts.tv_sec, srcPort, dstPort,
                //              [tmpCount, this](const QString &category) {
                //                  qDebug() << tmpCount << "的分类结果为: " << category;
                //                  emit this->PacketCapture::categoryReceived(tmpCount, category);
                //              });
                emit packetCaptured(info, httpBody, hexData);
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
            int headerLen = 0;
            for (int i = 0; i < 3 && isExtensionHeader(next_header); ++i) {
                if (header->len < sizeof(ether_header) + header_offset + 1) {
                    break;
                }

                const uint8_t* ext_header = packet + sizeof(ether_header) + header_offset;
                uint8_t ext_len = (ext_header[1] + 1) * 8;  // 扩展头长度单位是8字节

                headerLen = sizeof(ether_header) + header_offset + ext_len;
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

            updateFlowStats(srcAddr, dstAddr, header->len, header->ts, headerLen);

            // 构造显示信息
            QString info = QString("[%1] %2 → %3 %4 Len=%5 Time=%6.%7 Payload=%8 Next=%9")
                               .arg(++m_packetCount)//, 6, 10, QLatin1Char(' '))  // 包序号
                               .arg(srcAddr)                                  // 源IPv6
                               .arg(dstAddr)                                  // 目标IPv6
                               .arg(protocol)                                 // IPv6
                               .arg(header->len)                              // 总长度
                               .arg(header->ts.tv_sec)                        // 秒
                               .arg(header->ts.tv_usec, 6, 10, QLatin1Char('0')) // 微秒
                               .arg(payload_len)                              // 载荷长度
                               .arg(upperProtocol);                            // 上层协议

            qDebug() << m_packetCount << " IPv6 packet info formatted.";

            // int tmpCount = this->m_packetCount;
            // applyAIModel(srcAddr, dstAddr, protocol, header->ts.tv_sec, rawTcp.th_sport, rawTcp.th_dport,
            //              [tmpCount, this](const QString &category) {
            //                  qDebug() << tmpCount << "的分类结果为: " << category;
            //                  emit this->PacketCapture::categoryReceived(tmpCount, category);
            //              });
            emit packetCaptured(info, httpBody, hexData);
        }
        else if (eth_type == ETHERTYPE_ARP) {
            protocol = "ARP";
            // ARP 处理

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
                int headerLen = sizeof(ether_header) + sizeof(arp_header);
                updateFlowStats(srcMac, dstMac, header->len, header->ts, headerLen);
                QString info = QString("[%1] %2(%3) → %4(%5) ARP Len=%6 Time=%7.%8 %9")
                                   .arg(++m_packetCount)
                                   .arg(srcIp)
                                   .arg(srcMac)
                                   .arg(dstIp)
                                   .arg(dstMac)
                                   .arg(header->len)
                                   .arg(header->ts.tv_sec)
                                   .arg(header->ts.tv_usec)
                                   .arg(op);

                // int tmpCount = this->m_packetCount;
                // applyAIModel(srcAddr, dstAddr, protocol, header->ts.tv_sec, rawTcp.th_sport, rawTcp.th_dport,
                //              [tmpCount, this](const QString &category) {
                //                  qDebug() << tmpCount << "的分类结果为: " << category;
                //                  emit this->PacketCapture::categoryReceived(tmpCount, category);
                //              });

                emit packetCaptured(info, httpBody, hexData);
            } else {
                qWarning() << "Invalid ARP packet length";
            }
        }

        // 默认情况下仍输出基本信息
        if (protocol == "Unknown") {
            QString info = QString("[%1] Unknown → Unknown Unknown Len=%2 Time=%3.%4 ether_type=0x%5")
                .arg(++m_packetCount)
                .arg(header->len)
                .arg(header->ts.tv_sec)
                .arg(header->ts.tv_usec)
                .arg(eth_type, 0, 16);
            emit packetCaptured(info, "Unknown", "Unknown");
        }
    }

    pcap_close(m_pcapHandle);
    m_pcapHandle = nullptr;
}
