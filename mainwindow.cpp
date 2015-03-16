#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <QDropEvent>
#include <QMimeData>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    _readPcapFile = new ReadPcapFile();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::dropEvent(QDropEvent *ev)
{
#ifdef __linux
    QString file_name = ev->mimeData()->text().remove("file://");
#endif
#ifdef _WIN32
    QString file_name = ev->mimeData()->text().remove("file:///");
#endif
    //emit send_settings(file_name, (QStandardItemModel*)ui->tableView->model(), vheader, header);
    ///read_pcap_file->start();
    //setWindowTitle(file_name);
    _readPcapFile->setFileName(file_name);

    //QFileInfo file_info(file_name);
    //_file_name = file_info.fileName();

    //QApplication::setOverrideCursor(Qt::WaitCursor);
    qDebug() << "File name: " << file_name;
}

void MainWindow::dragEnterEvent(QDragEnterEvent *ev)
{
   ev->accept();
}
