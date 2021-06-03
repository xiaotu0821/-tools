#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "payload/ping_scan.h"
#include "payload/port_scan.h"
#include<QDebug>
#include<QMessageBox>
#include<QStringList>
#include<QThreadPool>
#include<QQueue>
#include <QTextBlock>
#include <QProcess>
#include<QFile>
#include<QFileInfo>
#include<QSettings>
#include<QTime>
#include<mythread.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    //存活探测------------
    void on_pushButton_4_clicked();
    void on_pushButton_clicked();
    void on_pushButton_3_clicked();
    void show_menu(const QPoint pos);
    void clickgoose();
    // 需要放置tcping.exe
    //放入nmap进行端口识别
    //端口扫描--------
     void on_pushButton_24_clicked();
    void radioBtnSlot_RCE();   //快速生成RCE端口
    void radioBtnSlot2_TOPthousand();
    void radioBtnSlot3_allport();


    void on_pushButton_startscan_clicked();

    void on_pushButton_stopscan_clicked();

    void on_pushButton_check_clicked();

    //------------------web相关
    void clickgoose_web();

    void on_import_file_clicked();
    void show_menu_web(const QPoint pos);
    void on_pushButton_start_web_clicked();

public:
    QStringList urls;
    QTime time;
     int thread_numer=10;
    int len=0;
    static int already_chececk_all_web;
    static int rowcount;
    QQueue<MyThread*>mythread;
    QString isshirotrue;
    QString isexptrue;
private:
    int already_chececk_all;
    int ping_number=0;
    int ipline;
    int  scan_number;
    int web_number;
    QStringList iplist;
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
