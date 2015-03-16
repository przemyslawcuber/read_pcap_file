#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "ReadPcapFile.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

protected:
    void dropEvent(QDropEvent *ev);
    void dragEnterEvent(QDragEnterEvent *ev);

private:
    Ui::MainWindow *ui;
    ReadPcapFile* _readPcapFile;
};

#endif // MAINWINDOW_H
