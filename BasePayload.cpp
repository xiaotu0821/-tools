#include "BasePayload.h"

QString BasePayload::gethost(QString url)  //不带端口
{

    if(url.startsWith("http"))
        {
        url=url.section('/',2,2);
        if(url.contains(':'))
            url=url.split(":")[0];
    }else
    {
        url=url.section('/',0,1);
        if(url.contains(':'))
            url=url.split(":")[0];
    }
    return url;
}

QString BasePayload::gethost(QString url,bool port)  //带端口
{
    if(port==true)
    {
    if(url.startsWith("http"))
        {
        url=url.section('/',2,2);


    }else
    {
        url=url.section('/',0,1);

    }
    return url;
    }
}

BasePayload::~BasePayload()
{

}
