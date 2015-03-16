#include <QThread>
#include <QList>
//#include "packageinfo.h"
#include <QStandardItemModel>
#include <QStandardItem>
//#include "QtCheckHeaderView.h"

#ifndef READPCAPFILE_H
#define READPCAPFILE_H

class ReadPcapFile : public QThread
{
    Q_OBJECT
public:
    ReadPcapFile();
    void setFileName(const QString &);
    QString getFileName();
    void run();

private:
    QString _fileName;

};

#endif // READPCAPFILE_H
