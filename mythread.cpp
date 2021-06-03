#include "mythread.h"

MyThread::MyThread(QString exp_names,int num)
{

        flag=0;
        exp_name=exp_names;
        number=num;


}

void MyThread::one_check()
{
    Exp_choose *exp=new Exp_choose(exp_name);
    qDebug()<<"已到这里....";
    bp=exp->retunr_exp_bp();
     qDebug()<<"已到这里地址....2"<<bp;
     qDebug()<<"已到这里....2";

     istrue=bp->checkVUL(url);
     qDebug().noquote()<<istrue<<"111111";
     shiro_result=bp->shiro_result;
     qDebug()<<"bp->payload="<<bp->payload;
     exp_name=bp->exp_name_all;
     extern_info=bp->kuozhan;
        emit retunr_info(url,exp_name,istrue,bp->payload,shiro_result,extern_info);

        delete  exp;
     exp=nullptr;
     delete bp;
     bp=nullptr;

}

void MyThread::all_check()
{
     Exp_choose *exp=new Exp_choose(exp_name);
   QQueue<BasePayload*> check_all_bp=exp->get_check_all_bp();   //如果报错，可能返回复制回有问题
   while(!check_all_bp.isEmpty()){
           istrue= check_all_bp.front()->checkVUL(url);
            shiro_result=check_all_bp.front()->shiro_result;
            qDebug()<<"bp->payload="<<check_all_bp.front()->payload;
              exp_name_all=check_all_bp.front()->exp_name_all;                  //该变量负责全部扫描时记录每一个exp_name的名称；
             qDebug()<<"exp_name"<<exp_name_all;
             extern_info=check_all_bp.front()->kuozhan;
            emit retunr_info(url,exp_name_all,istrue,check_all_bp.front()->payload,shiro_result,extern_info);
            QThread::usleep(2); //每个休眠10微秒
            delete check_all_bp.front();
            check_all_bp.pop_front();
   }
   delete  exp;
   exp=nullptr;

}
void MyThread::run()
{
    //可以在exp类里设置一个flag，对flag的值进行判断，如果为某个值，则返回一个exp queue，每个queue里存在一个类，进行全量扫描
    if(exp_name.startsWith("全漏洞探测"))
        {
        all_check();
    }else
    {
        one_check();
    }

}


MyThread::~MyThread()
{

   emit check_one_finish();


    qDebug()<<"线程退出......";

}
