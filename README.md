# -tools
漏洞探测小工具
说明：
	欢迎使用初梦的漏洞扫描工具。
    	本工具使用QT开发，开源，源码在github和公众号 ，也可以联系微信 xiaotian551973 	
使用前需安装：
	端口扫描：
	       tcping.exe  （用于存活性探测，可以自行下载配置环境变量即可）
	       nmap.exe   （用于端口探测，自行下载安装即可）
	       注意：当进行存活探测或端口探测时，建议不要将线程开启太大，否则会引起机器卡顿。
	
	web漏洞探测
	       需要安装 Win64OpenSSL_Light-1_1_1k.exe  ,用于连接https （已和程序一起打包）
其他配置：
	在config.ini 中，可以配置dnslog地址和是否检查shiro（vmware漏洞需要提前写好 dnslog 地址并需要手动查看dnslog接口界面）
					 （shiro 配置为true，检查只检查是否使用shiro，不探测shiro漏洞）
					
	cm1212.zip 用于验证 泛微 css 上传漏洞，不要删除。
使用说明：
        进行单个url探测时，在url 处输入url，点击check 按钮，如存在漏洞，会在下面展示出来。不存在漏洞则不展示。
       批量url探测时，在文件路径处输入文件路径，点击导入。
      在存活探测结果和web探测结果上单击鼠标右键，可以直接保存结果到txt中。
注意：请不要用于非法操作，一切操作与本人无关。 同时在对上一个版本中添加的命令执行功能进行删除。只用于探测，不用于执行命令。所有poc替换成无害poc。
	该软件探测原理（直接使用漏洞对每个url进行探测（即不进行指纹探测，直接尝试漏洞探测））


目前可以探测的漏洞：
    1. 宝塔数据库未授权访问漏洞
    2. 用友ERP-NC目录遍历漏洞
    3. 网康下一代防火墙RCE漏洞
    4. Jellyfin任意文件读取漏洞
    5. 亿邮电子邮件系统RCE漏洞
    6.锐捷上网行为管理账户密码泄露
    7.D-Link DCS 信息泄露
    8.VMware vRealize Manager SSRF漏洞
    9.MessageSolution 邮件归档系统EEA的通用型信息泄露漏洞
    10. 蓝凌OA漏洞
	蓝凌OA custom.jsp 任意文件读取漏洞
    11.泛微oa
	泛微云桥 e-Bridge 任意文件读取
	泛微OA Bsh 远程代码执行漏洞 CNVD-2019-32204
	泛微OA WorkflowCenterTreeData接口SQL注入(仅限oracle数据库) CNVD-2019-34241
	泛微OA V9 任意文件上传
	泛微OA css任意文件上传
    12.鸿信-公务车智能化管理服务平台任意文件上传
     13.C-Lodop云打印任意文件读取
	
