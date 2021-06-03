#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QObject>
#include<QRunnable>
#include<QDebug>
#include<QThread>
#include<QQueue>
#include<QQueue>
#include "exp_choose.h"
#include "BasePayload.h"
#include <QMap>
#include<QMutex>
class MyThread : public QObject,public QRunnable
{
    Q_OBJECT
public:
public:

    explicit MyThread(QObject *parent = nullptr);
    MyThread(QString,int);
    int number;//定位属于第几个url，用来发送信号
   // BasePayload *bp=nullptr;
    ~MyThread();
    QString extern_info;//接收扩展信息
    BasePayload *bp;
    QQueue<QString>queue;
     QMutex mutex;
    int startnum;
    int endnum;
    QString exp_name_all;//批量时记录每一个exp名称
    int flag=0;
    bool shiro_result=false;
    void one_check();
    void all_check();

QString exp_name;
    QString url;
public:
    virtual void run()Q_DECL_OVERRIDE;
    bool istrue=true;
signals:
    void retunr_info(QString,QString,bool,QString,bool,QString);

    void check_one_finish();

};

#endif // MYTHREAD_H
