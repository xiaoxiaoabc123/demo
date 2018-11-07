下面是插件判断，返回结果需要最终程序截图如有错误可以修复.
类型|条件|工具|返回结果
:---|:--|:---|:---|
系统服务|3306端口开放|mysql|获取当前数据库-如果是root，读取mysql密码并且破解
系统服务|21端口开放|hydra|获取文件目录列表
系统服务|8080端口开放|tomcat_mgr_login|返回系统中所有的war压缩包名称与tomcat版本信息
系统服务|873端口开放|rsync|返回当前未授权目录信息，卸载其中某个文件
系统服务|4848端口开放|glashfish|返回系统界面
系统服务|11211端口开放|netcat|memcache未授权访问，返回基本信息
系统服务|27017,28017端口开放|mongodb|返回show collections命令即可
系统服务|22端口开放|hydra|返回当前etc/passwd文件，如果是root，直接返回加密文件，即可破解显示
系统服务|23端口开放|hydra|登陆系统执行 whoami命令
系统服务|6379端口开放|redis|返回版本信息
waf判断|数据包返回内容存在：wangzhan.360.cn或者请求头存在：X-Powered-By-360wzb| 任意扫描方式|360 Web Application Firewall (360)
waf判断|数据包返回内容：aesecure_denied.png或者请求头存在：aeSecure-code|任意扫描方式|aeSecure (aeSecure)
WAF判断|re.search(r"\AAL[_-]?(SESS\|LB)")|任意扫描方式|Airlock (Phion/Ergon)
waf判断|请求头存在：X-Powered-By-Anquanbao或者返回包中存在/aqb_cc/error/, hidden_intercept_time|任意扫描方式	|Anquanbao Web Application Firewall (Anquanbao)
waf判断|情返回包中存在：This request has been blocked by website protection from Armor|任意扫描方式|Armor Protection (Armor Defense)
WAF判断|返回包内容存在：The requested URL was rejected. Please consult with your administrator或者This page can't be displayed. Contact support for additional information|任意扫描方式|Application Security Manager (F5 Networks)
waf判断|请求头中存在，譬如代码：re.search(r"\bAWS", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Amazon Web Services Web Application Firewall (Amazon)
waf判断|re.search(r"yunjiasu-nginx", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Yunjiasu Web Application Firewall (Baidu)
WAF判断|re.search(r"\Abarra_counter_session=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者re.search(r"(\A\|\b)barracuda_", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)|任意扫描方式|Barracuda Web Application Firewall (Barracuda Networks)
WAF判断|headers.get("X-Cnection", "").lower() == "close"或者headers.get("X-WA-Info")或者re.search(r"\bTS[0-9a-f]+=", headers.get(HTTP_HEADER.SET_COOKIE, ""))或者re.search(r"BigIP\|BIGipServer", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者re.search(r"BigIP\|BIGipServer", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者re.search(r"\AF5\Z", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|BIG-IP Application Security Manager (F5 Networks)
waf判断|re.search(r"BinarySec", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者请求头中存在x-binarysec-via, x-binarysec-nocache|任意扫描方式|BinarySEC Web Application Firewall (BinarySEC)
waf判断|re.search(r"BlockDos\.net", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|BlockDoS
WAF判断|headers.get("Powered-By-ChinaCache")|任意扫描方式|ChinaCache (ChinaCache Networks)
waf判断|re.search(r"ACE XML Gateway", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Cisco ACE XML Gateway (Cisco Systems)
waf判断|返回包中存有"Cloudbric", "Malicious Code Detected"|任意扫描方式|Cloudbric Web Application Firewall (Cloudbric)
waf服务|re.search(r"cloudflare", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者re.search(r"\A__cfduid=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者re.search(r"CloudFlare Ray ID:\|var CloudFlare=", page or "")或者headers.get("cf-ray")或者返回包中存在"Attention Required! \| Cloudflare", "Please complete the security check to access"，"Attention Required! \| Cloudflare", "Sorry, you have been blocked","CLOUDFLARE_ERROR_500S_BOX", "::CAPTCHA_BOX::"|任意扫描方式|CloudFlare Web Application Firewall (CloudFlare)
waf判断|re.search(r"Error from cloudfront", headers.get("X-Cache", ""), re.I)|任意扫描方式|CloudFront (Amazon)
waf判断|re.search(r"Protected by COMODO WAF", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Comodo Web Application Firewall (Comodo)
waf判断|返回包中存在："This site is protected by CrawlProtect"|任意扫描方式|CrawlProtect (Jean-Denis Brun)
waf判断|re.search(r"\A(OK\|FAIL)", headers.get("X-Backside-Transport", ""), re.I)|任意扫描方式|IBM WebSphere DataPower (IBM)
waf判断|re.search(r"\Asessioncookie=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者code == 200 and re.search(r"\ACondition Intercepted", page or "", re.I)|任意扫描方式|Deny All Web Application Firewall (DenyAll)
waf判断|headers.get("x-distil-cs") |任意扫描方式|Distil Web Application Firewall Security (Distil Networks)
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx
系统服务|内容|内容|xxxx



