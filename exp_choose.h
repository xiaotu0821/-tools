#ifndef EXP_CHOOSE_H
#define EXP_CHOOSE_H

#include <QObject>
#include <QMessageBox>
#include<QQueue>
#include "payload/baota_backdor.h"
#include "BasePayload.h"
#include "payload/yonsuittraversal.h"
#include "payload/netentsec.h"
#include "payload/jellyfin.h"
#include "payload/eyouemail.h"
#include "payload/ruijie.h"
#include "payload/d_link_dcs.h"
#include "payload/vmware_ssrf.h"
#include "payload/messagesolution.h"
#include "payload/landray_oa.h"
#include "payload/weaver_oa.h"
#include "payload/hx_car_manager.h"
#include "payload/c_lodop_read.h"
class Exp_choose : public QObject
{
    Q_OBJECT
public:
    explicit Exp_choose(QObject *parent = nullptr);
    Exp_choose(QString);
    BasePayload *bp=nullptr;
    QQueue <BasePayload*> check_all_bp;
    QString exp_name;

    BasePayload* retunr_exp_bp();
    QQueue<BasePayload*> get_check_all_bp();

signals:

};

#endif // EXP_CHOOSE_H
