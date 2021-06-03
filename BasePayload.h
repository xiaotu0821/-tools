#ifndef BASEPAYLOAD_H
#define BASEPAYLOAD_H
#include<QString>
#include<QStringList>
class BasePayload
   {
public:
    BasePayload(){};
    virtual bool checkVUL(QString)= 0;
    //bool shiro=false;
    bool result=false;
    bool shiro_result=false;
    bool all_check=false;
    QString kuozhan=" ";
    QString exp_name_all="无漏洞"; //返回每一个exp的漏洞名称
    QString payload;
    virtual QString cmd_exec(QString url,QString cmd)=0;
    virtual ~BasePayload();
    QString gethost(QString url);
    QString gethost(QString url,bool);


};
//Q_DECLARE_INTERFACE(BasePayload, "接口类，必须实现纯虚函数/漏洞检测基类")
#endif // BASEPAYLOAD_H
