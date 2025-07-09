#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLineEdit>
#include <QStatusBar>
#include "packetcapture.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void startCapture();
    void stopCapture();
    void updatePacketList(const QString &packetInfo);
    void refreshDevices();
    void captureFinished();

private:
    void setupUI();
    void populateDevices();

    PacketCapture *packetCapture;
    QThread *captureThread;

    // UI Components
    QComboBox *deviceComboBox;
    QLineEdit *filterEdit;
    QPushButton *startButton;
    QPushButton *stopButton;
    QPushButton *refreshButton;
    QListWidget *packetList;
    QStatusBar *statusBar;
};

#endif // MAINWINDOW_H
