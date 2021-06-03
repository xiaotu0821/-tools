#ifndef HTTPREQUEST_H
#define HTTPREQUEST_H
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include<QSettings>
#include<QTextCodec>
#include<QString>
#include<QMessageBox>
#include<QDebug>
#include<QEventLoop>
#include<QTimer>
#include<QNetworkCookie>
class Httprequest : public QObject
{
    Q_OBJECT
public:
    Httprequest();
    ~Httprequest();
public:

    QByteArray PostBody;  //https://blog.csdn.net/qq_25600055/article/details/53517278
     int Timeout=10000;
     QString shiro="false";
     bool shiro_result=false;
     QString dnslog;
     QVariant cookie;
     QString webcame="false";
     bool webcame_result=false;
     QVariant shexiangtou_cookie;
public:
     int status_code;

     void postHttpRequest(QString requestUrl,QString encoding,QString contentType,QByteArray postdata);
     void request(QString requestUrl, int timeOut, QString requestMethod, QString contentType,QString ContentLength, QByteArray postQString,QString encoding, QString Disposttion,QString UserAgent,QString SOAPAction);
     void getHttpReuest(QString requestUrl,QString encoding,QString ContentType);
     void getHttpReuest(QString requestUrl,QString encoding) ;
     void postHttpRequest(QString requestUrl,QString encoding,QString commod);
     void postfileHttpRequest(QString requestUrl,QString encoding,QString filename,QByteArray fileContent,QString file_mime);
     void post_soap_request(QString requestUrl, QString contentType,QString ContentLength, QByteArray postQString,QString encoding, QString UserAgent,QString SOAPAction);
     QByteArray respons_data;
     QNetworkRequest req;
     QString upload_file="file";
     QNetworkAccessManager *manager=new QNetworkAccessManager;
    QNetworkReply *reply;
     void clear();

private slots:
    void ReceiveReply(QNetworkReply *reply);

signals:

};
#endif // HTTPREQUEST_H
