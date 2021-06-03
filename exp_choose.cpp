#include "exp_choose.h"

Exp_choose::Exp_choose(QObject *parent) : QObject(parent)
{

}
#include "exp_choose.h"
Exp_choose::Exp_choose(QString exp_name)
{
        this->exp_name=exp_name;
}

QQueue<BasePayload*> Exp_choose::get_check_all_bp()
{
    if(this->exp_name.startsWith("全漏洞探测"))
        {
            check_all_bp.append(new baota_backdor);
            check_all_bp.append(new NetEntSec);
            check_all_bp.append(new Jellyfin);
            check_all_bp.append(new EyouEmail);
            check_all_bp.append(new ruijie);
            check_all_bp.append(new D_Link_DCS);
            check_all_bp.append(new VMware_ssrf);
            check_all_bp.append(new MessageSolution);
            check_all_bp.append(new Landray_OA);
            check_all_bp.append(new weaver_oa);
            check_all_bp.append(new hx_car_manager);
            check_all_bp.append(new C_Lodop_read);
        }
    return check_all_bp;
}
BasePayload* Exp_choose::retunr_exp_bp()
{

    if(this->exp_name.startsWith("宝塔数据库未授权访问"))
     {
       bp = new baota_backdor;

    }else if(this->exp_name.startsWith("用友ERP-NC目录遍历"))
        {
        bp=new  YonSuitTraversal;
    }else if(this->exp_name.startsWith("网康下一代防火墙"))
    {
       bp=new NetEntSec;
    }else if(this->exp_name.startsWith("Jellyfin"))
        {
        bp=new Jellyfin;
    }else if(this->exp_name.startsWith("亿邮电子邮件系统"))
    {
        bp=new EyouEmail;
    }else if(this->exp_name.startsWith("锐捷上网行为管理"))
        {
        bp=new ruijie;
    }else if(this->exp_name.startsWith("D-Link DCS"))
        {
        bp=new D_Link_DCS;
    }else if(this->exp_name.startsWith("VMware vRealize"))
    {

        bp=new VMware_ssrf;
    }else if(this->exp_name.startsWith("MessageSolution"))
    {
        bp=new MessageSolution;
    }else if(this->exp_name.startsWith("蓝凌OA"))
    {
             bp=new Landray_OA;
    }else if(this->exp_name.startsWith("泛微OA"))
    {
            bp=new weaver_oa;
    }else if (this->exp_name.startsWith("鸿信-公务车智能化管理"))
    {
        bp=new hx_car_manager;
    }else if(this->exp_name.startsWith("C-Lodop云打印任意文件读取"))
    {
        bp=new C_Lodop_read;
    }
    return bp;
}

