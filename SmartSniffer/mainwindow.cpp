#include "mainwindow.h"
#include <pcap.h>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), packetCapture(nullptr), captureThread(nullptr)
{
    setupUI();
    populateDevices();
}

MainWindow::~MainWindow()
{
    stopCapture();
}

void MainWindow::setupUI()
{
    // Central widget and layout
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // Device selection
    QHBoxLayout *deviceLayout = new QHBoxLayout();
    deviceLayout->addWidget(new QLabel("Network Device:"));

    deviceComboBox = new QComboBox();
    deviceLayout->addWidget(deviceComboBox);

    refreshButton = new QPushButton("Refresh");
    connect(refreshButton, &QPushButton::clicked, this, &MainWindow::refreshDevices);
    deviceLayout->addWidget(refreshButton);

    mainLayout->addLayout(deviceLayout);

    // Filter section
    QHBoxLayout *filterLayout = new QHBoxLayout();
    filterLayout->addWidget(new QLabel("Filter:"));

    filterEdit = new QLineEdit();
    filterEdit->setPlaceholderText("e.g., tcp, udp, port 80");
    filterLayout->addWidget(filterEdit);

    mainLayout->addLayout(filterLayout);

    // Control buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    startButton = new QPushButton("Start Capture");
    connect(startButton, &QPushButton::clicked, this, &MainWindow::startCapture);

    stopButton = new QPushButton("Stop Capture");
    connect(stopButton, &QPushButton::clicked, this, &MainWindow::stopCapture);
    stopButton->setEnabled(false);

    buttonLayout->addWidget(startButton);
    buttonLayout->addWidget(stopButton);
    mainLayout->addLayout(buttonLayout);

    // Packet list
    packetList = new QListWidget();
    mainLayout->addWidget(packetList);

    // Status bar
    statusBar = new QStatusBar();
    setStatusBar(statusBar);

    setCentralWidget(centralWidget);
    setWindowTitle("Smart Packet Sniffer");
    resize(800, 600);
}

void MainWindow::populateDevices()
{
    deviceComboBox->clear();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        QMessageBox::warning(this, "Error", QString("Failed to find devices: %1").arg(errbuf));
        return;
    }

    for (pcap_if_t *d = devices; d != nullptr; d = d->next) {
        deviceComboBox->addItem(d->name);
    }

    pcap_freealldevs(devices);
}

void MainWindow::refreshDevices()
{
    populateDevices();
}

void MainWindow::startCapture()
{
    if (deviceComboBox->currentIndex() < 0) {
        QMessageBox::warning(this, "Error", "No network device selected!");
        return;
    }

    stopCapture(); // Ensure previous capture is stopped

    packetCapture = new PacketCapture();
    captureThread = new QThread();

    // Configure capture
    packetCapture->setDeviceName(deviceComboBox->currentText());
    if (!filterEdit->text().isEmpty()) {
        packetCapture->setFilterRule(filterEdit->text());
    }

    // Move capture to thread
    packetCapture->moveToThread(captureThread);

    // Connect signals - FIXED: Use public methods instead of protected run()
    connect(captureThread, &QThread::started, packetCapture, &PacketCapture::startCapture);
    connect(packetCapture, &PacketCapture::packetCaptured, this, &MainWindow::updatePacketList);
    connect(packetCapture, &PacketCapture::finished, this, &MainWindow::captureFinished);
    connect(captureThread, &QThread::finished, packetCapture, &PacketCapture::deleteLater);

    // Start thread
    captureThread->start();

    // Update UI
    startButton->setEnabled(false);
    stopButton->setEnabled(true);
    packetList->clear();
    statusBar->showMessage("Capture started on " + deviceComboBox->currentText());
}

void MainWindow::stopCapture()
{
    if (packetCapture) {
        packetCapture->stopCapture();
    }

    if (captureThread && captureThread->isRunning()) {
        captureThread->quit();
        captureThread->wait();
        delete captureThread;
        captureThread = nullptr;
    }

    packetCapture = nullptr;

    // Update UI
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    statusBar->showMessage("Capture stopped");
}

void MainWindow::updatePacketList(const QString &packetInfo)
{
    packetList->addItem(packetInfo);
    packetList->scrollToBottom();
}

void MainWindow::captureFinished()
{
    stopCapture();
    statusBar->showMessage("Capture completed");
}
