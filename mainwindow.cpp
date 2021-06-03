#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tableWidget_ipisalive->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tableWidget_web->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->tableWidget_ipisalive,SIGNAL(customContextMenuRequested(QPoint)),this,SLOT(show_menu(QPoint)));
    connect(ui->tableWidget_web,SIGNAL(customContextMenuRequested(QPoint)),this,SLOT(show_menu_web(QPoint)));
    connect(ui->radioButton_5, SIGNAL(toggled( bool)), this, SLOT(radioBtnSlot_RCE())); //RCE端口
    connect(ui->radioButton_6, SIGNAL(toggled( bool)), this, SLOT(radioBtnSlot2_TOPthousand()));//1000个端口
    connect(ui->radioButton_7, SIGNAL(toggled( bool)), this, SLOT(radioBtnSlot3_allport()));//全端口
    ui->tableWidget_ipport_scan->setColumnCount(5);
    QStringList header;
       header << "IP" << "端口" << "服务" << "状态"<<"其他";
        ui->tableWidget_ipport_scan->setHorizontalHeaderLabels(header);
        ui->tableWidget_ipport_scan->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        QFileInfo fileinfo("config.ini");
        if(!fileinfo.isFile())
        {
            QSettings setting("config.ini",QSettings::IniFormat);
        setting.beginGroup("dnsPlatform");
        setting.setValue("dnslog","you dnslog address");
        setting.endGroup();
        setting.beginGroup("shirocheck");
        setting.setValue("shiro","true or false");
        setting.endGroup();
        }
   // ping.run();

}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_4_clicked() //载入IP
{
    iplist.clear();
    if(ui->lineEdit_filepath->text()!=NULL || !ui->lineEdit_filepath->text().toStdString().empty())
        {
        QString filepath=ui->lineEdit_filepath->text();
        if(filepath.startsWith("\u202A"))  //去除windows复制时的特殊字符
            filepath=filepath.remove("\u202A");
        if(filepath==NULL||filepath.isEmpty())
            QMessageBox::warning(this,"warning","获取文件句柄为空");
        QFile file(filepath);
        if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
           {
              QMessageBox::warning(this,"warning","无法打开文件");
           }
        QByteArray line;
        while(!file.atEnd())
           {
               line = file.readLine();
              if(!line.simplified().isEmpty())
               iplist.append(QString::fromUtf8(line).simplified());

           }
        foreach (QString ip, iplist) {
            ui->plainTextEdit_iparea->appendPlainText(ip);
        }
}
}

void MainWindow::on_pushButton_clicked()
{
    ui->tableWidget_ipisalive->clear();
    ui->pushButton->setEnabled(false);
    QQueue<ping_scan*>ping;
    iplist.clear();
     ipline=ui->plainTextEdit_iparea->document()->lineCount();
     if(ui->plainTextEdit_iparea->document()->isEmpty())
     {
         QMessageBox::warning(this,"warning","请载入ip或输入ip");
         return;
     }
     for(int i=0;i<ipline;i++)
     {

         if( ui->plainTextEdit_iparea->document()->findBlockByLineNumber(i).text()!="")
           {

             iplist.append(ui->plainTextEdit_iparea->document()->findBlockByLineNumber(i).text());

         }

     }
     ui->plainTextEdit_iparea->clear();
     foreach (QString ip, iplist) {
         ui->plainTextEdit_iparea->appendPlainText(ip);
     }
     ipline=iplist.count(); //重新获取去除空格等之后的行数
     int tcping_tmp=0;
     if(ui->radioButton_tcping->isChecked())
     {
         tcping_tmp=1;
     }
     already_chececk_all=1;
     ui->label_count->setNum(ipline);
     int thread_number=ui->lineEdit_threadcount->text().toInt();  //获取输入的线程数
      QThreadPool::globalInstance()->setMaxThreadCount(thread_number);
      ping_number=ui->tableWidget_ipisalive->rowCount(); //用于增加一行的数据
      for (int i=0;i<ipline ;i++ ) {
          ping.append(new ping_scan(iplist.at(i),tcping_tmp));

          connect(ping.at(i),&ping_scan::commandSuccessed,this,[this](QString ip,int tcping)
          {
             ui->tableWidget_ipisalive->setRowCount(ping_number+1);
             ui->tableWidget_ipisalive->setItem(ping_number,0,new QTableWidgetItem(ip));
             ui->tableWidget_ipisalive->setItem(ping_number,1,new QTableWidgetItem(QString::number(tcping)));
             ++ping_number;
              ui->label_currcurrent->setNum(already_chececk_all++);

             if(already_chececk_all==ipline)
             {
                 ui->pushButton->setEnabled(true);
             }
          });
          connect(ping.at(i),&ping_scan::commandfail,this,[this]()
          {


             ui->label_currcurrent->setNum(already_chececk_all++);
             if(already_chececk_all==ipline)
             {
                 ui->pushButton->setEnabled(true);
             }
          }
             );}


      while(!ping.isEmpty()){
                QThreadPool::globalInstance()->start(ping.front());
                QThread::usleep(10); //每个休眠10微秒
                ping.pop_front();

      }


}

void MainWindow::clickgoose() //保存txt对应的槽函数
{
    QString filepath="ping_result_ip.txt";
    QFile file(filepath);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
       {
          QMessageBox::warning(this,"warning","无法打开文件");
       }
    for (int i=0;i<ui->tableWidget_ipisalive->rowCount() ;i++ ) {
        file.write(ui->tableWidget_ipisalive->item(i,0)->text().toUtf8()+"\n");


    }
    file.close();
    QMessageBox::warning(this,"提示","已保存，查看ping_result_ip.txt");
}
void MainWindow::clickgoose_web() //保存web漏洞txt对应的槽函数
{
    QString filepath="web_result.txt";
    QFile file(filepath);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
       {
          QMessageBox::warning(this,"warning","无法打开文件");
       }
    QString content;
    for (int i=0;i<ui->tableWidget_web->rowCount();i++ ) {
        content="";
        content+= ui->tableWidget_web->item(i,0)->text();
        content+="\t";
        content+= ui->tableWidget_web->item(i,1)->text();
        content+="\t";
        content+= ui->tableWidget_web->item(i,2)->text();
        content+="\t";
        content+= ui->tableWidget_web->item(i,3)->text();
        content+="\t";
        content+= ui->tableWidget_web->item(i,4)->text();
        content+="\t";
        content+= ui->tableWidget_web->item(i,5)->text();
        file.write(content.toUtf8()+"\n");
    }
    file.close();
    QMessageBox::warning(this,"提示","已保存，查看web_result.txt");
}
void MainWindow::show_menu(const QPoint pos)
{
//设置菜单选项
QMenu *menu = new QMenu(ui->tableWidget_ipisalive);
QAction *pnew = new QAction("保存为txt",ui->tableWidget_ipisalive);
QAction *pnew1 = new QAction("发送到端口扫描",ui->tableWidget_ipisalive);
connect (pnew,SIGNAL(triggered()),this,SLOT(clickgoose()));
connect (pnew1,SIGNAL(triggered()),this,SLOT(clickmms()));
menu->addAction(pnew);
menu->addAction(pnew1);
menu->move (cursor ().pos ());
menu->show ();
}

void MainWindow::show_menu_web(const QPoint pos)
{
//设置菜单选项
QMenu *menu_web = new QMenu(ui->tableWidget_web);
QAction *pnew_web = new QAction("保存结果为txt",ui->tableWidget_web);
connect (pnew_web,SIGNAL(triggered()),this,SLOT(clickgoose_web()));
menu_web->addAction(pnew_web);
menu_web->move (cursor ().pos ());
menu_web->show ();
}
void MainWindow::on_pushButton_3_clicked() //停止按钮
{
    int thread= QThreadPool::globalInstance()->activeThreadCount();
    if(thread!=0)
    {

    QThreadPool::globalInstance()->clear();
    QThreadPool::globalInstance()->waitForDone(); //等待所有线程完成
    QMessageBox::warning(this,"warning","已经全部停止。。。。");
    ui->pushButton->setEnabled(true);
    ui->pushButton->setText("重新开始");
    ui->pushButton->repaint();
    ui->pushButton_3->setEnabled(false);
    }else
    {
    QMessageBox::warning(this,"提示","还没开始任务呢大兄弟！");
    }
}


//-----------------------------------------从这里开始，端口扫描用的，但iplist为全场通用，主要负责记录ip，每次用之前清空

void MainWindow::on_pushButton_24_clicked()   //载入要扫描的ip文件
{
    iplist.clear();
    if(ui->lineEdit_filepath_scan->text()!=NULL || !ui->lineEdit_filepath_scan->text().toStdString().empty())
        {
        QString filepath=ui->lineEdit_filepath_scan->text();
        if(filepath.startsWith("\u202A"))  //去除windows复制时的特殊字符
            filepath=filepath.remove("\u202A");
        if(filepath==NULL||filepath.isEmpty())
            QMessageBox::warning(this,"warning","获取文件句柄为空");
        QFile file(filepath);
        if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
           {
              QMessageBox::warning(this,"warning","无法打开文件");
           }
        QByteArray line;
        while(!file.atEnd())
           {
               line = file.readLine();
              if(!line.simplified().isEmpty())
               iplist.append(QString::fromUtf8(line).simplified());

           }
        foreach (QString ip, iplist) {
            ui->plainTextEdit_iparea_scan->appendPlainText(ip);
            }
        }
}

void MainWindow::radioBtnSlot_RCE()
{
 if(ui->radioButton_5->isChecked())
 {
    ui->lineEdit_scanport->clear();
     ui->lineEdit_scanport->setText("21,22,23,445,389,3389,80,443,8080,7001,3306,1433,1521,6379,27017,2375,5900,5432");
 }
}

void MainWindow::radioBtnSlot2_TOPthousand()
{
    ui->lineEdit_scanport->clear();
     ui->lineEdit_scanport->setText("20-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50050,50300,50389,50500,50636,50800,51111,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389");
}


void MainWindow::radioBtnSlot3_allport()
{
    ui->lineEdit_scanport->clear();
   ui->lineEdit_scanport->setText("1-65535");
}

void MainWindow::on_pushButton_startscan_clicked() //点击开始扫描端口
{


    ui->tableWidget_ipport_scan->clearContents();
    ui->pushButton_startscan->setEnabled(false);
    QQueue<port_scan*>scan;
    iplist.clear();
     ipline=ui->plainTextEdit_iparea_scan->document()->lineCount();
     if(ui->plainTextEdit_iparea_scan->document()->isEmpty())
     {
         QMessageBox::warning(this,"warning","请载入ip或输入ip");
         return;
     }
     for(int i=0;i<ipline;i++)
     {

         if( ui->plainTextEdit_iparea_scan->document()->findBlockByLineNumber(i).text()!="")
           {

             iplist.append(ui->plainTextEdit_iparea_scan->document()->findBlockByLineNumber(i).text());

         }

     }
     ui->plainTextEdit_iparea_scan->clear();
     foreach (QString ip, iplist) {
         ui->plainTextEdit_iparea_scan->appendPlainText(ip);
     }
     ipline=iplist.count(); //重新获取去除空格等之后的行数

     already_chececk_all=1;
     ui->label_count_scan->setNum(ipline);
     int thread_number=ui->lineEdit_threadcount_scan->text().toInt();  //获取输入的线程数
      QThreadPool::globalInstance()->setMaxThreadCount(thread_number);
     scan_number=ui->tableWidget_ipport_scan->rowCount(); //用于增加一行的数据
      for (int i=0;i<ipline ;i++ ) {
        scan.append(new port_scan(iplist.at(i),ui->lineEdit_scanport->text()));//放入端口

          connect(scan.at(i),&port_scan::commandSuccessed,this,[this](QString ip,QString port,QString service)
          {

             ui->tableWidget_ipport_scan->setRowCount(scan_number+1);
             ui->tableWidget_ipport_scan->setItem(scan_number,0,new QTableWidgetItem(ip));
             ui->tableWidget_ipport_scan->setItem(scan_number,1,new QTableWidgetItem(port));
             ui->tableWidget_ipport_scan->setItem(scan_number,2,new QTableWidgetItem(service));
             ui->tableWidget_ipport_scan->item(scan_number,0)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
             ui->tableWidget_ipport_scan->item(scan_number,1)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
             ui->tableWidget_ipport_scan->item(scan_number,2)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);

             scan_number+=1;

          });
          connect(scan.at(i),&port_scan::commandfail,this,[]()
          {

                ;

          }
             );
        connect(scan.at(i),&port_scan::finish_one_ip,this,[this]()
        {

            ui->label_currcurrent_scan->setNum(already_chececk_all);
            if(already_chececk_all>=ipline)
            {
                ui->pushButton_startscan->setEnabled(true);

            }
            already_chececk_all++;
        }
        );

      }
      while(!scan.isEmpty()){
                QThreadPool::globalInstance()->start(scan.front());
                QThread::usleep(1); //每个休眠10微秒
                scan.pop_front();

      }
}



void MainWindow::on_pushButton_stopscan_clicked()  //停止多线程
{
    int thread= QThreadPool::globalInstance()->activeThreadCount();
    if(thread!=0)
    {

    QThreadPool::globalInstance()->clear();
    QThreadPool::globalInstance()->waitForDone(); //等待所有线程完成
    QMessageBox::warning(this,"warning","已经全部停止。。。。");
    ui->pushButton_startscan->setEnabled(true);
    ui->pushButton_startscan->setText("重新开始");
    ui->pushButton_startscan->repaint();
    ui->pushButton_stopscan->setEnabled(false);
    }else
    {
    QMessageBox::warning(this,"提示","还没开始任务呢大兄弟！");
    }
}

//--------------------------------Web漏洞探测---------------------------------
int MainWindow::rowcount=0;
int MainWindow::already_chececk_all_web=0;



void MainWindow::on_pushButton_check_clicked()
{

    already_chececk_all_web=0;
    rowcount=1;
    if(ui->lineEdit_url->text().isEmpty())
    {
        QMessageBox::warning(this,"提示","请输入地址");
        return ;
    }
    mythread.clear();
    mythread.append(new MyThread(ui->comboBox_exp->currentText(),0));
    web_number=0;
     QString line_url=ui->lineEdit_url->text();
     mythread.at(0)->url=line_url;
     //ui->tableWidget_web->clearContents();
     for (int i = ui->tableWidget_web ->rowCount() - 1; i > -1; i--)
     {
         ui->tableWidget_web->removeRow(i);
     }
    ui->label_current_task->setNum(0);
    ui->label_count_task->setNum(1);
    ui->pushButton_check->setEnabled(false);
    time.start();



        connect((mythread.at(0)),&MyThread::retunr_info,this,[this](QString url,QString exp_name ,bool istrue,QString payload,bool shiro_result,QString othre)
                    {
                                //number参数可以去掉
                        isshirotrue = shiro_result ? "true;" : "false;";//判断是否存在shiro
                        isexptrue =istrue? "true;":"false;";
                        ui->label_minute->setNum(time.elapsed()/60000);
                        qDebug()<<"isshir...."<<isshirotrue;
                        if(istrue || isshirotrue.contains("true")) //存在漏洞时
                        {
                            ui->tableWidget_web->setRowCount(web_number+1);
                             ui->tableWidget_web->setItem(web_number,0,new QTableWidgetItem(url)); //expname
                            ui->tableWidget_web->setItem(web_number,1,new QTableWidgetItem(exp_name)); //expname
                            ui->tableWidget_web->setItem(web_number,2,new QTableWidgetItem(isexptrue));
                            ui->tableWidget_web->setItem(web_number,3,new QTableWidgetItem(payload)); //判断是否存在漏洞

                            ui->tableWidget_web->setItem(web_number,4,new QTableWidgetItem(isshirotrue));

                            ui->tableWidget_web->setItem(web_number,5,new QTableWidgetItem(othre));
                           ui->tableWidget_web->item(web_number,0)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           ui->tableWidget_web->item(web_number,1)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                            ui->tableWidget_web->item(web_number,2)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           ui->tableWidget_web->item(web_number,3)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           ui->tableWidget_web->item(web_number,4)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           ui->tableWidget_web->item(web_number,5)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           web_number+=1;

                           ui->tableWidget_web->repaint();
                        }
                        else
                        {
                        // ui->tableWidget_url->setItem(number,1,new QTableWidgetItem("false"));
                         //ui->tableWidget_url->repaint();
                        }

                        ui->label_minute->setNum(time.elapsed()/60000);


        });
        connect(mythread.at(0),&MyThread::check_one_finish,this,[this]()
        {
            ui->label_current_task->setNum(++already_chececk_all_web);
            if(already_chececk_all_web>=rowcount)
            {
                ui->pushButton_check->setEnabled(true);
            }

        });
        while(!mythread.isEmpty()){
                  QThreadPool::globalInstance()->start(mythread.front());
                  mythread.pop_front();

        }



}






















void MainWindow::on_pushButton_start_web_clicked()
{
    rowcount=0;
    mythread.clear();
    iplist.clear();
     ipline=ui->tableWidget_web->rowCount();
     for(int i=0;i<ipline;i++)
     {

         if( !ui->tableWidget_web->item(i,0)->text().isEmpty())
           {

             iplist.append(ui->tableWidget_web->item(i,0)->text());

         }

     }
     //ui->tableWidget_web->clearContents();
     for (int i = ui->tableWidget_web ->rowCount() - 1; i > -1; i--)
     {
         ui->tableWidget_web->removeRow(i);
     }
     foreach (QString ip, iplist) {
         ui->plainTextEdit_iparea_scan->appendPlainText(ip);
     }
     ipline=iplist.count();


    ui->pushButton_stop->setEnabled(true);
    ui->pushButton_start_web->setEnabled(false);
    time.start();
    already_chececk_all_web=1;
    thread_numer=ui->lineEdit_thread->text().toInt();
    ui->label_count_task->setNum(ipline);
    ui->label_count_task->repaint();
    rowcount=ipline;
    QThreadPool::globalInstance()->setMaxThreadCount(thread_numer);
    web_number=ui->tableWidget_web->rowCount();


    ui->label_count_task->setNum(rowcount);
    for (int i=0;i<rowcount ;i++ )
        {

        //map.insert(ui->tableWidget_url->item(i,1)->text().toInt(),ui->tableWidget_url->item(i,0)->text());
      //  queue.append(ui->tableWidget_url->item(i,0)->text());

         //mythread.append());

        mythread.append(new MyThread(ui->comboBox_exp->currentText(),i));
        mythread.at(i)->url=iplist.at(i);
        mythread.at(i)->setAutoDelete(true);

        connect(mythread.at(i),&MyThread::retunr_info,this,[this](QString url,QString exp_name ,bool istrue,QString payload,bool shiro_result,QString othre)
                    {
                                //number参数可以去掉
                        isshirotrue = shiro_result ? "true" : "false";//判断是否存在shiro
                        isexptrue =istrue? "true":"false";
                        ui->label_minute->setNum(time.elapsed()/60000);
                        qDebug()<<"isshir...."<<isshirotrue;
                        if(istrue || isshirotrue.contains("true")) //存在漏洞时
                        {
                            ui->tableWidget_web->setRowCount(web_number+1);
                             ui->tableWidget_web->setItem(web_number,0,new QTableWidgetItem(url)); //expname
                            ui->tableWidget_web->setItem(web_number,1,new QTableWidgetItem(exp_name)); //expname
                            ui->tableWidget_web->setItem(web_number,2,new QTableWidgetItem(isexptrue));
                            ui->tableWidget_web->setItem(web_number,3,new QTableWidgetItem(payload)); //判断是否存在漏洞

                            ui->tableWidget_web->setItem(web_number,4,new QTableWidgetItem(isshirotrue));

                            ui->tableWidget_web->setItem(web_number,5,new QTableWidgetItem(othre));
                           ui->tableWidget_web->item(web_number,0)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           ui->tableWidget_web->item(web_number,1)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                            ui->tableWidget_web->item(web_number,2)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           ui->tableWidget_web->item(web_number,3)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           ui->tableWidget_web->item(web_number,4)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           ui->tableWidget_web->item(web_number,5)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                           web_number+=1;

                           ui->tableWidget_web->repaint();
                        }
                        else
                        {
                        // ui->tableWidget_url->setItem(number,1,new QTableWidgetItem("false"));
                         //ui->tableWidget_url->repaint();
                        }


                        ui->label_minute->setNum(time.elapsed()/60000);


        });
        connect(mythread.at(0),&MyThread::check_one_finish,this,[this]()
        {
            ui->label_current_task->setNum(already_chececk_all_web++);
            if(already_chececk_all_web>=rowcount)
            {
                ui->pushButton_start_web->setEnabled(true);
            }

        });
     }

      while(!mythread.isEmpty()){
                QThreadPool::globalInstance()->start(mythread.front());
                mythread.pop_front();

      }
}

void MainWindow::on_import_file_clicked()
{
    urls.clear();
    ui->tableWidget_web->clearContents();
    if(ui->lineEdit_filepath_web->text()!=NULL || !ui->lineEdit_filepath_web->text().toStdString().empty())
        {
        QString filepath=ui->lineEdit_filepath_web->text();
        if(filepath.startsWith("\u202A"))
            filepath=filepath.remove("\u202A");
        qDebug()<<filepath;
        if(filepath==NULL||filepath.isEmpty())
            QMessageBox::warning(this,"warning","获取文件句柄为空");
        QFile file(filepath);
        if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
           {
              QMessageBox::warning(this,"warning","无法打开文件");
           }
        QByteArray line;
        while(!file.atEnd())
           {
               line = file.readLine();
              if(!line.simplified().isEmpty())
               urls.append(QString::fromUtf8(line).simplified());

           }
            len=urls.length();
            int i =0;
            ui->tableWidget_web->setRowCount(len);
            ui->tableWidget_web->verticalHeader()->setDefaultSectionSize(10);
            ui->tableWidget_web->horizontalHeader()->resizeSection(0,200);
            ui->tableWidget_web->horizontalHeader()->resizeSection(1,120);
            foreach(QString s , urls )
            {
                qDebug()<<s;// 遍历所有url
               ui->tableWidget_web->setItem(i,0,new QTableWidgetItem(s));
               i++;
            }

        }else
    {
        QMessageBox::warning(this,"warning","请输入文件地址");
    }
    ui->pushButton_start_web->setEnabled(true);
}


