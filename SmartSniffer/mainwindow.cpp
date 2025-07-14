#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QTextStream>
#include <QHeaderView>
#include <QDateTime>
#include <QMessageBox>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <tchar.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_capture(new PacketCapture(this))
{
    ui->setupUi(this);
    initializeUi();
    loadInterfaces();
    connectSignals();

    connect(m_capture, &PacketCapture::packetCaptured,
            this, &MainWindow::handlePacketCaptured);
}

MainWindow::~MainWindow()
{
    m_capture->onStopCapture();
    m_capture->wait();
    delete ui;
}

void MainWindow::initializeUi()
{
    setMenuBar(ui->menubar);
    addToolBar(ui->mainToolBar);
    statusBar()->showMessage(tr("就绪"));
    ui->tablePackets->setColumnCount(8);
    ui->tablePackets->setHorizontalHeaderLabels(
        {tr("序号"), tr("时间戳"), tr("源IP"), tr("目的IP"), tr("协议"), tr("长度"), tr("FLAG"), tr("AI 标记")});
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tablePackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tablePackets->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->actionStartCapture->setEnabled(true);
    ui->actionStopCapture->setEnabled(false);
}

QString getFriendlyName(const char *adapterName) {
    // adapterName 的形式是 \Device\NPF_{GUID}，我们要提取出 {GUID}
    QString fullName = QString::fromUtf8(adapterName);
    int startIdx = fullName.indexOf('{');
    int endIdx = fullName.indexOf('}');

    if (fullName.endsWith("Loopback"))
        return QString("Loopback");

    QString guid = fullName.mid(startIdx, endIdx - startIdx + 1).toUpper();

    qDebug() << guid << '\n';

    // 获取所有适配器信息
    ULONG bufferSize = 15000;
    IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(bufferSize);

    if (!pAddresses)
        return QString();

    DWORD dwRet = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &bufferSize);
    if (dwRet == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(bufferSize);
        dwRet = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &bufferSize);
    }

    QString result = "未知设备";

    if (dwRet == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *pCurr = pAddresses; pCurr != nullptr; pCurr = pCurr->Next) {
            if (pCurr->AdapterName) {
                qDebug() << pCurr->AdapterName << "\t" << QString::fromWCharArray(pCurr->FriendlyName) << "\n";
                if (QString(pCurr->AdapterName).toUpper() == guid.toUpper()) {
                    result = QString::fromWCharArray(pCurr->FriendlyName);
                    break;
                }
            }
        }
    }

    if (pAddresses)
        free(pAddresses);

    return result;
}

void MainWindow::loadInterfaces()
{
    ui->comboInterface->clear();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        QMessageBox::warning(this, "Error", QString("Failed to find devices: %1").arg(errbuf));
        return;
    }

    for (pcap_if_t *d = devices; d != nullptr; d = d->next) {
        QString rawName = QString(d->name);
        QString friendlyName = getFriendlyName(d->name);

        QString displayName;
        if (!friendlyName.isEmpty()) {
            displayName = QString("%1 (%2)").arg(friendlyName, rawName);
        } else {
            displayName = rawName;
        }

        ui->comboInterface->addItem(displayName, rawName); // 第二个参数保留原始 device 名
    }

    pcap_freealldevs(devices);
}

void MainWindow::connectSignals()
{
    connect(ui->actionStartCapture, &QAction::triggered, this, &MainWindow::onStartCapture);
    connect(this, &MainWindow::startCapture, m_capture, &PacketCapture::onStartCapture);

    connect(ui->actionStopCapture, &QAction::triggered, this, &MainWindow::onStopCapture);
    connect(this, &MainWindow::stopCapture, m_capture, &PacketCapture::onStopCapture);

    connect(ui->actionExport, &QAction::triggered, this, &MainWindow::onExportData);

    connect(ui->btnApplyFilter, &QPushButton::clicked, this, &MainWindow::onApplyFilter);

    connect(ui->tablePackets, &QTableWidget::itemSelectionChanged,
            this, &MainWindow::onPacketSelected);

    connect(m_capture, &PacketCapture::packetCaptured,
            this, &MainWindow::handlePacketCaptured);
}

QString MainWindow::getCurrInterfaceName()
{
    int selectedIndex = ui->comboInterface->currentIndex();
    QString rawName = ui->comboInterface->itemData(selectedIndex).toString();
    return rawName;
}

void MainWindow::onStartCapture()
{
    QString iface = getCurrInterfaceName();
    QString filter = ui->editFilter->text();

    emit configChanged({iface, filter});
    emit startCapture(iface, filter);

    ui->actionStartCapture->setEnabled(false);
    ui->actionStopCapture->setEnabled(true);

    qDebug() << "startCapture emitted.\n";
    statusBar()->showMessage(tr("抓包已启动"));
}

void MainWindow::onStopCapture()
{
    emit stopCapture();

    ui->actionStartCapture->setEnabled(true);
    ui->actionStopCapture->setEnabled(false);

    qDebug() << "stopCapture emitted.\n";
    statusBar()->showMessage(tr("抓包已停止"));
}

void MainWindow::onApplyFilter()
{
    ConfigData cfg{getCurrInterfaceName(), ui->editFilter->text()};
    emit configChanged(cfg);
    statusBar()->showMessage(tr("过滤规则已应用"));
}

void MainWindow::onExportData()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("导出为 CSV"), {}, tr("CSV 文件 (*.csv)"));
    if (fileName.isEmpty()) return;
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QTextStream out(&file);
    for (int r = 0; r < ui->tablePackets->rowCount(); ++r) {
        for (int c = 0; c < ui->tablePackets->columnCount(); ++c) {
            out << ui->tablePackets->item(r, c)->text();
            if (c < ui->tablePackets->columnCount()-1) out << ',';
        }
        out << '\n';
    }
    statusBar()->showMessage(tr("导出完成"));
}

void MainWindow::onPacketSelected()
{
    int row = ui->tablePackets->currentRow();
    if (row >= 0) showDetails(row);
}

void MainWindow::handlePacketCaptured(const QString &packetInfo)
{
    // 解析 packetInfo 并封装为 Packet 类型
    // TODO: 实现解析逻辑
    qDebug() << packetInfo << "\n";
    Packet pkt;

    // QString("[%1] %2 → %3 %4 Len=%5 Time=%6 Flags=%7")
    QStringList parts = packetInfo.split(' ');
    qDebug() << parts.value(0) << " " << parts.value(1) << " " << parts.value(2) << " " << parts.value(3) << " " << parts.value(4) << " " << parts.value(5) << " " << parts.value(6) << "\n";
    pkt.id = parts.value(0).split('[')[0].split(']')[0];
    pkt.timestamp = parts.value(5).remove("Time=");
    pkt.srcIP = parts.value(1);
    pkt.dstIP = parts.value(3);
    pkt.protocol = parts.value(4);
    pkt.length = parts.value(6).remove("Len=").toInt();
    pkt.flags = parts.last().remove("Flags=");
    // emit receivePacket(pkt);
    appendPacketRow(pkt);
}

void MainWindow::appendPacketRow(const Packet &pkt)
{
    int row = ui->tablePackets->rowCount();
    ui->tablePackets->insertRow(row);
    ui->tablePackets->setItem(row, 0, new QTableWidgetItem(pkt.id));
    ui->tablePackets->setItem(row, 1, new QTableWidgetItem(pkt.timestamp));
    ui->tablePackets->setItem(row, 2, new QTableWidgetItem(pkt.srcIP));
    ui->tablePackets->setItem(row, 3, new QTableWidgetItem(pkt.dstIP));
    ui->tablePackets->setItem(row, 4, new QTableWidgetItem(pkt.protocol));
    ui->tablePackets->setItem(row, 5, new QTableWidgetItem(QString::number(pkt.length)));
    // ui->tablePackets->setItem(row, 6, new QTableWidgetItem(pkt.aiTag));
}

void MainWindow::showDetails(int row)
{
    ui->textRaw->setPlainText(tr("Raw data for row %1").arg(row));
    ui->textHex->setPlainText(tr("Hex data for row %1").arg(row));
    ui->textParsed->setPlainText(tr("Parsed data for row %1").arg(row));
}

