#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QTextStream>
#include <QHeaderView>
#include <QDateTime>

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
    m_capture->stopCapture();
    m_capture->wait();
    delete ui;
}

void MainWindow::initializeUi()
{
    setMenuBar(ui->menubar);
    addToolBar(ui->mainToolBar);
    statusBar()->showMessage(tr("就绪"));
    ui->tablePackets->setColumnCount(6);
    ui->tablePackets->setHorizontalHeaderLabels(
        {tr("时间"), tr("源IP"), tr("目的IP"), tr("协议"), tr("长度"), tr("AI标记")});
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tablePackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tablePackets->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void MainWindow::loadInterfaces()
{
    // TODO: 获取并填充系统网络接口列表
    ui->comboInterface->addItem("\\Device\\NPF_{example}");
}

void MainWindow::connectSignals()
{
    connect(ui->actionStartCapture, &QAction::triggered, this, &MainWindow::onStartCapture);
    connect(ui->actionStopCapture, &QAction::triggered, this, &MainWindow::onStopCapture);
    connect(ui->actionExport, &QAction::triggered, this, &MainWindow::onExportData);

    connect(ui->btnApplyFilter, &QPushButton::clicked, this, &MainWindow::onApplyFilter);

    connect(ui->tablePackets, &QTableWidget::itemSelectionChanged,
            this, &MainWindow::onPacketSelected);

    connect(m_capture, &PacketCapture::packetCaptured,
            this, &MainWindow::handlePacketCaptured);
}

void MainWindow::onStartCapture()
{
    QString iface = ui->comboInterface->currentText();
    QString filter = ui->editFilter->text();
    emit configChanged({iface, filter});
    emit startCapture(iface, filter);
    statusBar()->showMessage(tr("抓包已启动"));
}

void MainWindow::onStopCapture()
{
    emit stopCapture();
    statusBar()->showMessage(tr("抓包已停止"));
}

void MainWindow::onApplyFilter()
{
    ConfigData cfg{ui->comboInterface->currentText(), ui->editFilter->text()};
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
    Packet pkt;
    QStringList parts = packetInfo.split(' ');
    pkt.timestamp = parts.value(0);
    pkt.srcIP = parts.value(1);
    pkt.dstIP = parts.value(3);
    pkt.protocol = parts.value(4);
    pkt.length = parts.value(5).remove("Len=").toInt();
    pkt.aiTag = parts.last();
    emit receivePacket(pkt);
}

void MainWindow::appendPacketRow(const Packet &pkt)
{
    int row = ui->tablePackets->rowCount();
    ui->tablePackets->insertRow(row);
    ui->tablePackets->setItem(row, 0, new QTableWidgetItem(pkt.timestamp));
    ui->tablePackets->setItem(row, 1, new QTableWidgetItem(pkt.srcIP));
    ui->tablePackets->setItem(row, 2, new QTableWidgetItem(pkt.dstIP));
    ui->tablePackets->setItem(row, 3, new QTableWidgetItem(pkt.protocol));
    ui->tablePackets->setItem(row, 4, new QTableWidgetItem(QString::number(pkt.length)));
    ui->tablePackets->setItem(row, 5, new QTableWidgetItem(pkt.aiTag));
}

void MainWindow::showDetails(int row)
{
    ui->textRaw->setPlainText(tr("Raw data for row %1").arg(row));
    ui->textHex->setPlainText(tr("Hex data for row %1").arg(row));
    ui->textParsed->setPlainText(tr("Parsed data for row %1").arg(row));
}
