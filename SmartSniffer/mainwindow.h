#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "packetcapture.h"
#include <QString>
#include <QStringList>

// 自定义数据结构，可根据需要调整
struct Packet {
    QString timestamp;
    QString srcIP;
    QString dstIP;
    QString protocol;
    int length;
    QString aiTag;
};

struct AlertInfo {
    QString message;
    int severity;
};

struct ConfigData {
    QString device;
    QString filter;
};

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

signals:
    void startCapture(const QString &device, const QString &filter);
    void stopCapture();
    void receivePacket(const Packet &pkt);
    void displayAlert(const AlertInfo &info);
    void configChanged(const ConfigData &data);

private slots:
    void onStartCapture();    // 响应按钮点击，发送startCapture
    void onStopCapture();     // 响应按钮点击，发送stopCapture
    void onApplyFilter();     // 配置变更，发送configChanged
    void onExportData();
    void onPacketSelected();
    void handlePacketCaptured(const QString &packetInfo); // 将后端信号转为receivePacket

private:
    Ui::MainWindow *ui;
    PacketCapture *m_capture;

    void initializeUi();
    void connectSignals();
    void loadInterfaces();
    void appendPacketRow(const Packet &pkt);
    void showDetails(int row);
};

#endif // MAINWINDOW_H
