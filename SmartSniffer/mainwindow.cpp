#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QTextStream>
#include <QHeaderView>
#include <QDateTime>
#include <QMessageBox>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>

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
    , m_networkManager(new QNetworkAccessManager(this))
{
    ui->setupUi(this);
    initializeUi();
    loadInterfaces();
    connectSignals();

    // QThread *workerThread = new QThread;
    // m_capture->moveToThread(workerThread);
    // workerThread->start();
    // QMetaObject::invokeMethod(m_capture, "initNetwork", Qt::QueuedConnection);

    memset(packetList, 0, sizeof(packetList));
    listHead = listTail = removedRowCount = 0;

    aiServerProcess = new QProcess(this);
    aiServerProcess->start("ai_server.exe");

    if (!aiServerProcess->waitForStarted(30000))
        qDebug() << "AI Server failed to start.";
    else
        qDebug() << "AI Server started.";
}

MainWindow::~MainWindow()
{
    m_capture->onStopCapture();
    m_capture->wait();
    aiServerProcess->terminate();
    aiServerProcess->waitForFinished();
    delete ui;
}

void MainWindow::initializeUi()
{
    addToolBar(ui->mainToolBar);
    statusBar()->showMessage(tr("就绪"));
    ui->tablePackets->setColumnCount(8);
    ui->tablePackets->setHorizontalHeaderLabels(
        {tr("序号"), tr("时间戳"), tr("源IP"), tr("目的IP"), tr("协议"), tr("长度"), tr("其他信息"), tr("AI 标记")});
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

    qDebug() << guid;

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
                // qDebug() << pCurr->AdapterName << "\t" << QString::fromWCharArray(pCurr->FriendlyName) << "\n";
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
    connect(this, &MainWindow::configChanged, m_capture, &PacketCapture::onConfigChanged);

    connect(ui->tablePackets, &QTableWidget::itemSelectionChanged, this, &MainWindow::onPacketSelected);

    connect(m_capture, &PacketCapture::packetCaptured, this, &MainWindow::handlePacketCaptured);

    connect(m_capture, &PacketCapture::applyAIModel, this, &MainWindow::handleApplyAIModel);
    connect(this, &MainWindow::categoryReceived, this, &MainWindow::setAILabel);
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
    qDebug() << "configChanged emitted.";

    emit startCapture();

    ui->actionStartCapture->setEnabled(false);
    ui->actionStopCapture->setEnabled(true);

    qDebug() << "startCapture emitted.";
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
    bool toRestart = this->m_capture->isCapturing();
    if (toRestart)
        emit stopCapture();
    emit configChanged(cfg);
    statusBar()->showMessage(tr("过滤规则已应用"));
    if (toRestart)
        emit startCapture();
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
            QTableWidgetItem *item = ui->tablePackets->item(r, c);
            if (item) // 只有非空才取值
                out << item->text();
            if (c < ui->tablePackets->columnCount() - 1)
                out << ',';
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

void MainWindow::handlePacketCaptured(const QString &packetInfo, const QString &httpBody, const QString &hexData)
{
    qDebug() << packetInfo;
    Packet pkt;

    // QString("[%1] %2 → %3 %4 Len=%5 Time=%6 Flags=%7")
    QStringList parts = packetInfo.split(' ');
    // qDebug() << parts.value(0) << " " << parts.value(1) << " " << parts.value(2) << " " << parts.value(3) << " " << parts.value(4) << " " << parts.value(5) << " " << parts.value(6);
    pkt.id = parts.value(0).remove("[").remove("]");
    pkt.timestamp = parts.value(6).remove("Time=");
    pkt.srcIP = parts.value(1);
    pkt.dstIP = parts.value(3);
    pkt.protocol = parts.value(4);
    pkt.length = parts.value(5).remove("Len=").toInt();
    pkt.extraInfos = "";
    for (int i = 7; i < parts.length(); i ++)
        pkt.extraInfos += parts.value(i) + ' ';
    pkt.extraInfos.removeLast();

    pkt.httpBody = httpBody;
    pkt.hexData = hexData;
    pkt.parsedData = packetInfo;

    packetList[listTail] = pkt;
    listTail = (listTail + 1) % TABLE_SIZE;
    appendPacketRow(pkt);
}

void MainWindow::handleApplyAIModel(QByteArray data, int packetId)
{
    qDebug() << "Sending data: " << data.toStdString();
    if (!m_networkManager) {
        m_networkManager = new QNetworkAccessManager(this);
    }

    QNetworkRequest request(QUrl("http://127.0.0.1:5001/predict"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = m_networkManager->post(request, data);

    connect(reply, &QNetworkReply::finished, this, [=]() {
        int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        qDebug() << "[AI] HTTP status code:" << statusCode;

        QByteArray response = reply->readAll();
        qDebug() << "[AI] Raw response:" << response;

        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(response, &err);

        if (err.error != QJsonParseError::NoError) {
            qWarning() << "[AI] JSON parse error:" << err.errorString();
            emit categoryReceived(packetId, "N/A");
        } else {
            QJsonObject obj = doc.object();
            QString category = obj.value("category").toString("N/A");
            qDebug() << "[AI] Prediction for packet" << packetId << ":" << category;
            emit categoryReceived(packetId, category);
        }

        reply->deleteLater();
    });
}

void MainWindow::setAILabel(const int packetId, const QString category)
{
    if (packetId <= removedRowCount) return;
    int idx = (packetId + removedRowCount) % TABLE_SIZE;
    qDebug() << "Setting AI Label for packet " << packetId;
    ui->tablePackets->setItem(idx, 7, new QTableWidgetItem(category));
}

void MainWindow::appendPacketRow(const Packet &pkt)
{
    qDebug() << "Appending row for packet " << pkt.id;
    if (ui->tablePackets->rowCount() >= TABLE_SIZE) {
        ui->tablePackets->removeRow(0);
        removedRowCount ++;
    }

    int row = ui->tablePackets->rowCount();
    ui->tablePackets->insertRow(row);
    ui->tablePackets->setItem(row, 0, new QTableWidgetItem(pkt.id));
    ui->tablePackets->setItem(row, 1, new QTableWidgetItem(pkt.timestamp));
    ui->tablePackets->setItem(row, 2, new QTableWidgetItem(pkt.srcIP));
    ui->tablePackets->setItem(row, 3, new QTableWidgetItem(pkt.dstIP));
    ui->tablePackets->setItem(row, 4, new QTableWidgetItem(pkt.protocol));
    ui->tablePackets->setItem(row, 5, new QTableWidgetItem(QString::number(pkt.length)));
    ui->tablePackets->setItem(row, 6, new QTableWidgetItem(pkt.extraInfos));
    // if (pkt.protocol == "IPv6" || pkt.protocol == "ARP")
    ui->tablePackets->setItem(row, 7, new QTableWidgetItem("N/A"));
    ui->tablePackets->scrollToBottom();
}

void MainWindow::showDetails(int row)
{
    int idx = (row + removedRowCount) % TABLE_SIZE;
    ui->hexContent->setPlainText(packetList[idx].hexData);
    ui->rawContent->setPlainText(packetList[idx].httpBody);
    ui->parsedContent->setPlainText(packetList[idx].parsedData);
}

