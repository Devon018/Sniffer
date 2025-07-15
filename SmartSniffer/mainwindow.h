#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QStringList>
#include <QProcess>
#include <QNetworkAccessManager>
#include "packetcapture.h"

struct Packet {
    // 表格信息
    QString id;
    QString timestamp;
    QString srcIP;
    QString dstIP;
    QString protocol;
    int length;
    QString extraInfos;
    QString aiTag;

    // 详细信息
    QString httpBody;
    QString hexData;
    QString parsedData;
};

struct AlertInfo {
    QString message;
    int severity;
};

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

const int TABLE_SIZE = 500;

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
    void categoryReceived(int packetId, const QString category);

private slots:
    void onStartCapture();    // 开始按钮点击，发送startCapture
    void onStopCapture();     // 停止按钮点击，发送stopCapture
    void onApplyFilter();     // 配置变更，发送configChanged
    void onExportData();
    void onPacketSelected();
    void handlePacketCaptured(const QString &packetInfo, const QString &httpBody, const QString &hexData);
    void handleApplyAIModel(QByteArray data, int packetId);
    void setAILabel(int packetId, const QString category);

private:
    Ui::MainWindow *ui;
    PacketCapture *m_capture;
    Packet packetList[TABLE_SIZE];
    int listHead, listTail, removedRowCount;
    QProcess *aiServerProcess;
    QNetworkAccessManager *m_networkManager;

    void initializeUi();
    void connectSignals();
    void loadInterfaces();
    QString getCurrInterfaceName();
    void appendPacketRow(const Packet &pkt);
    void showDetails(int row);
};

#endif // MAINWINDOW_H
