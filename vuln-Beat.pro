QT       += core gui network xml

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    BasePayload.cpp \
    exp_choose.cpp \
    httprequest.cpp \
    main.cpp \
    mainwindow.cpp \
    mythread.cpp \
    payload/baota_backdor.cpp \
    payload/c_lodop_read.cpp \
    payload/d_link_dcs.cpp \
    payload/eyouemail.cpp \
    payload/hx_car_manager.cpp \
    payload/jellyfin.cpp \
    payload/landray_oa.cpp \
    payload/messagesolution.cpp \
    payload/netentsec.cpp \
    payload/ping_scan.cpp \
    payload/port_scan.cpp \
    payload/ruijie.cpp \
    payload/vmware_ssrf.cpp \
    payload/weaver_oa.cpp \
    payload/yonsuittraversal.cpp

HEADERS += \
    BasePayload.h \
    exp_choose.h \
    httprequest.h \
    mainwindow.h \
    mythread.h \
    payload/baota_backdor.h \
    payload/c_lodop_read.h \
    payload/d_link_dcs.h \
    payload/eyouemail.h \
    payload/hx_car_manager.h \
    payload/jellyfin.h \
    payload/landray_oa.h \
    payload/messagesolution.h \
    payload/netentsec.h \
    payload/ping_scan.h \
    payload/port_scan.h \
    payload/ruijie.h \
    payload/vmware_ssrf.h \
    payload/weaver_oa.h \
    payload/yonsuittraversal.h

FORMS += \
    mainwindow.ui

TRANSLATIONS += \
    vuln-Beat_zh_CN.ts

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
