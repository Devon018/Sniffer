#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QObject>
#include <QAtomicInteger>
#include <pcap.h>
#include <qthread.h>
#include "configdata.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

// Windows 下自定义 IP 头结构体
#pragma pack(push, 1)
typedef struct ip_header {
    unsigned char  ip_hl:4;     // 头长度
    unsigned char  ip_v:4;      // 版本
    unsigned char  ip_tos;      // 服务类型
    unsigned short ip_len;      // 总长度
    unsigned short ip_id;       // 标识
    unsigned short ip_off;      // 分片偏移
    unsigned char  ip_ttl;      // 生存时间
    unsigned char  ip_proto;    // 协议
    unsigned short ip_sum;      // 校验和
    struct in_addr ip_src;      // 源地址
    struct in_addr ip_dst;      // 目的地址
} ip_header;
#pragma pack(pop)
#endif

#ifdef _WIN32
// Windows 下自定义 TCP 头结构体
#pragma pack(push, 1)
typedef struct tcp_header {
    USHORT th_sport;    // 源端口
    USHORT th_dport;    // 目的端口
    ULONG  th_seq;      // 序列号
    ULONG  th_ack;      // 确认号
    UCHAR  th_offx2;    // 数据偏移和保留位
    UCHAR  th_flags;    // 标志位
    USHORT th_win;      // 窗口大小
    USHORT th_sum;      // 校验和
    USHORT th_urp;      // 紧急指针
} tcp_header;
#pragma pack(pop)

// Windows 下 TCP 标志位定义
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#else
#include <netinet/tcp.h>  // Linux/Mac 使用标准头文件
#endif

#ifdef _WIN32
// Windows 下自定义 UDP 头结构体
#pragma pack(push, 1)
typedef struct udp_header {
    USHORT uh_sport;    // 源端口
    USHORT uh_dport;    // 目的端口
    USHORT uh_ulen;     // UDP长度
    USHORT uh_sum;      // 校验和
} udp_header;
#pragma pack(pop)
#else
#include <netinet/udp.h>  // Linux/Mac 使用标准头文件
#endif

#ifdef _WIN32
// Windows 下自定义 IPv6 头结构体
#pragma pack(push, 1)
typedef struct ip6_hdr {
    ULONG   ip6_flow;    // 流标签和版本
    USHORT  ip6_plen;    // 载荷长度
    UCHAR   ip6_nxt;     // 下一个头部
    UCHAR   ip6_hlim;    // 跳数限制
    IN6_ADDR ip6_src;    // 源地址
    IN6_ADDR ip6_dst;    // 目的地址
} ip6_hdr;
#pragma pack(pop)

#define IPPROTO_ICMPV6   58  // Windows 需要手动定义
#else
#include <netinet/ip6.h>  // Linux/Mac 使用标准头文件
#endif

#ifdef _WIN32
// Windows 下自定义 ARP 头结构体
#pragma pack(push, 1)
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
#pragma pack(pop)

#else
#include <netinet/arp.h>  // Linux/Mac 使用标准头文件
#endif

class PacketCapture : public QThread
{
    Q_OBJECT
public:
    explicit PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();

    bool isCapturing();
    void setDeviceName(const QString &deviceName);
    void setFilterRule(const QString &filterRule);

signals:
    void packetCaptured(const QString &packetInfo, const QString &httpBody, const QString &hexData);

public slots:
    void onStartCapture();
    void onStopCapture();
    void onConfigChanged(const ConfigData &config);

protected:
    void run() override;

private:
    pcap_t *m_pcapHandle = nullptr;
    QString m_deviceName;
    QString m_filterRule;
    QAtomicInteger<quint32> m_stop;
    QAtomicInteger<unsigned long long> m_packetCount{0};

    QString extractPayload(const u_char* packet, const struct pcap_pkthdr* header);

    bool isExtensionHeader(uint8_t header_type) {
        return (header_type == 0) ||    // Hop-by-Hop
               (header_type == 43) ||   // Routing
               (header_type == 44) ||   // Fragment
               (header_type == 60) ||   // Destination Options
               (header_type == 51) ||   // AH
               (header_type == 50);     // ESP
    }
};

#endif // PACKETCAPTURE_H
