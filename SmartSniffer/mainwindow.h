#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QStringList>
#include "packetcapture.h"

struct Packet {
    QString id;
    QString timestamp;
    QString srcIP;
    QString dstIP;
    QString protocol;
    int length;
    QString flags;
    QString aiTag;
};

struct AlertInfo {
    QString message;
    int severity;
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
    void startCapture();
    void stopCapture();
    void receivePacket(const Packet &pkt);
    void displayAlert(const AlertInfo &info);
    void configChanged(const ConfigData &data);

private slots:
    void onStartCapture();    // 开始按钮点击，发送startCapture
    void onStopCapture();     // 停止按钮点击，发送stopCapture
    void onApplyFilter();     // 配置变更，发送configChanged
    void onExportData();
    void onPacketSelected();
    void handlePacketCaptured(const QString &packetInfo);

private:
    Ui::MainWindow *ui;
    PacketCapture *m_capture;

    void initializeUi();
    void connectSignals();
    void loadInterfaces();
    QString getCurrInterfaceName();
    void appendPacketRow(const Packet &pkt);
    void showDetails(int row);
};

#endif // MAINWINDOW_H
