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
waf判断|re.search(r"DOSarrest", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者headers.get("X-DIS-Request-ID")|任意扫描方式|DOSarrest (DOSarrest Internet Security)
waf判断|headers.get("X-dotDefender-denied", "")或者返回包中存在"dotDefender Blocked Your Request", '<meta name="description" content="Applicure is the leading provider of web application security', "Please contact the site administrator, and provide the following Reference ID:"|任意扫描方式|dotDefender (Applicure Technologies)
waf判断|re.search(r"\AECDF", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|EdgeCast Web Application Firewall (Verizon)
waf判断|返回包中存在"Invalid GET Data"|任意扫描方式|ExpressionEngine (EllisLab)
waf判断|re.search(r"\AFORTIWAFSID=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者是返回包中存在(".fgd_icon", ".blocked", ".authenticate")|任意扫描方式|FortiWeb Web Application Firewall (Fortinet)
waf判断|re.search(r"\AODSESSION=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)|任意扫描方式|Hyperguard Web Application Firewall (art of defence)
waf判断|re.search(r"incap_ses\|visid_incap", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者re.search(r"Incapsula", headers.get("X-CDN", ""), re.I)或者返回包中存在"Incapsula incident ID", "_Incapsula_Resource?", "?subject=WAF Block Page:"，Application Firewall Error", "If you feel you have been blocked in error, please contact Customer Support|任意扫描方式|Incapsula Web Application Firewall (Incapsula/Imperva)
waf判断|返回包中存在"The server denied the specified Uniform Resource Locator (URL). Contact the server administrator."，"The ISA Server denied the specified Uniform Resource Locator (URL)"|任意扫描方式|ISA Server (Microsoft)
waf判断|re.search(r"jiasule-WAF", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者re.search(r"__jsluid=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者 re.search(r"jsl_tracking", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者re.search(r"static\.jiasule\.com/static/js/http_error\.js", page or "", re.I)或者返回包中存在"notice-jiasule"|任意扫描方式|Jiasule Web Application Firewall (Jiasule)
waf判断|re.search(r"url\('/ks-waf-error\.png'\)", page or "", re.I)|任意扫描方式|KS-WAF (Knownsec)
waf判断|返回包中存在"Access Denied", "You don't have permission to access", "on this server", "Reference"，或者re.search(r"AkamaiGHost", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|KONA Security Solutions (Akamai Technologies)
waf判断|re.search(r"Mod_Security\|NOYB", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者返回包中存在"This error was generated by Mod_Security", "One or more things in your request were suspicious", "rules of the mod_security module"|任意扫描方式|ModSecurity: Open Source Web Application Firewall (Trustwave)
waf判断|re.search(r"naxsi/waf", headers.get(HTTP_HEADER.X_DATA_ORIGIN, ""), re.I)|任意扫描方式|NAXSI (NBS System)
waf判断|re.search(r"\ANCI__SessionId=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)|任意扫描方式|NetContinuum Web Application Firewall (NetContinuum/Barracuda Networks)
waf判断|re.search(r"\Aclose", headers.get("Cneonction", "") or headers.get("nnCoection", ""), re.I)或者re.search(r"\A(ns_af=\|citrix_ns_id\|NSC_)", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者re.search(r"\ANS-CACHE", headers.get(HTTP_HEADER.VIA, ""), re.I)|任意扫描方式|NetScaler (Citrix Systems)
waf判断|re.search(r"newdefend", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Newdefend Web Application Firewall (Newdefend)
waf判断|re.search(r"NSFocus", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|NSFOCUS Web Application Firewall (NSFOCUS)
waf判断|re.search(r"has been blocked in accordance with company policy", page or "", re.I)|任意扫描方式|Palo Alto Firewall (Palo Alto Networks)
waf判断|re.search(r"\APLBSID=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者re.search(r"Profense", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Profense Web Application Firewall (Armorlogic)
waf判断|re.search(r"Unauthorized Activity Has Been Detected.+Case Number:", page or "", re.I \| re.S)或者headers.get("X-SL-CompState")|任意扫描方式|AppWall (Radware)
waf判断|re.search(r"\Arbzid=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)或者re.search(r"Reblaze Secure Web Gateway", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Reblaze Web Application Firewall (Reblaze)
waf判断|返回包中存在"ASP.NET has detected data in the request that is potentially dangerous"，"Request Validation has detected a potentially dangerous client input value"， "HttpRequestValidationException"|任意扫描方式|ASP.NET RequestValidationMode (Microsoft)
waf判断|re.search(r"Safe3WAF", headers.get(HTTP_HEADER.X_POWERED_BY, ""), re.I)或者re.search(r"Safe3 Web Firewall", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Safe3 Web Application Firewall
waf判断|re.search(r"WAF/2\.0", headers.get(HTTP_HEADER.X_POWERED_BY, ""), re.I)或者re.search(r"Safedog", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者re.search(r"safedog", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)|任意扫描方式|Safedog Web Application Firewall (Safedog)
waf判断|re.search(r"SecureIIS[^<]+Web Server Protection", page or "")或者re.search(r"\?subject=[^>]*SecureIIS Error", page or "")或者返回包中存在"http://www.eeye.com/SecureIIS/"|任意扫描方式|SecureIIS Web Server Security (BeyondTrust)
waf判断|返回包中存在"SENGINX-ROBOT-MITIGATION"|任意扫描方式|SEnginx (Neusoft Corporation)
waf判断|返回包中存在"SiteLock Incident ID", "sitelock-site-verification", "sitelock_shield_logo"|任意扫描方式|TrueShield Web Application Firewall (SiteLock)
waf判断|返回包存在"This request is blocked by the SonicWALL"或者re.search(r"Web Site Blocked.+\bnsa_banner", page or "", re.I)或者re.search(r"SonicWALL", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|SonicWALL (Dell)
waf判断|返回包中存在"Powered by UTM Web Protection"|任意扫描方式|UTM Web Protection (Sophos)
waf判断|re.search(r"\AX-Mapping-", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)|任意扫描方式|Stingray Application Firewall (Riverbed / Brocade)
waf判断|re.search(r"Sucuri/Cloudproxy", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者re.search(r"Questions\?.+cloudproxy@sucuri\.net", (page or ""))或者在返回包中存在"Access Denied - Sucuri Website Firewall"，"Sucuri WebSite Firewall - CloudProxy - Access Denied"或者headers.get("X-Sucuri-ID")、headers.get("X-Sucuri-Cache")|任意扫描方式|CloudProxy WebSite Firewall (Sucuri)
waf判断|code == 405 and "waf.tencent-cloud.com" in (page or "")|任意扫描方式|Tencent Cloud Web Application Firewall (Tencent Cloud Computing)
waf判断|re.search(r"\Ast8(id\|_wat\|_wlf)", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)|任意扫描方式|Teros/Citrix Application Firewall Enterprise (Teros/Citrix Systems)
waf判断|re.search(r"F5-TrafficShield", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者re.search(r"\AASINFO=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)|任意扫描方式|TrafficShield (F5 Networks)
waf判断|re.search(r"Rejected-By-UrlScan", headers.get(HTTP_HEADER.LOCATION, ""), re.I)或者re.search(r"/Rejected-By-UrlScan", page or "", re.I)|任意扫描方式|UrlScan (Microsoft)
waf判断|re.search(r"Secure Entry Server", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|USP Secure Entry Server (United Security Providers)
waf判断|re.search(r"\bXID: \d+", page or "")或者返回包中存在"Request rejected by xVarnish-WAF"|任意扫描方式|Varnish FireWall (OWASP)
waf判断|re.search(r"nginx-wallarm", headers.get(HTTP_HEADER.SERVER, ""), re.I)|任意扫描方式|Wallarm Web Application Firewall (Wallarm)
waf判断|code >= 400 and re.search(r"\AWatchGuard", headers.get(HTTP_HEADER.SERVER, ""), re.I) |任意扫描方式|WatchGuard (WatchGuard Technologies)
waf判断|re.search(r"WebKnight", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者返回包中存在"WebKnight Application Firewall Alert", "AQTRONIX WebKnight"|任意扫描方式|WebKnight Application Firewall (AQTRONIX)
waf判断|re.search(r"This response was generated by Wordfence", page or "", re.I)或者re.search(r"Your access to this site has been limited", page or "", re.I)|任意扫描方式|Wordfence (Feedjit)
waf判断|re.search(r"YUNDUN", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者re.search(r"YUNDUN", headers.get("X-Cache", ""), re.I)|任意扫描方式|Yundun Web Application Firewall (Yundun)
waf判断|re.search(r"<img class=\"yunsuologo\"", page, re.I)或者re.search(r"yunsuo_session", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I)|任意扫描方式|Yunsuo Web Application Firewall (Yunsuo)
waf判断|re.search(r"\AZENEDGE", headers.get(HTTP_HEADER.SERVER, ""), re.I)或者返回包中存在"Your request has been blocked", "Incident ID", "/__zenedge/assets/"|任意扫描方式|Zenedge Web Application Firewall (Zenedge)
mysql所有可能注入| <error regexp="SQL syntax.*?MySQL"/> <error regexp="Warning.*?mysql_"/> <error regexp="MySqlException \(0x"/\> <error regexp="MySQLSyntaxErrorException"/>  <error regexp="valid MySQL result"/> <error regexp="check the manual that corresponds to your (MySQL\|MariaDB) server version"/><error regexp="Unknown column "'[^ ]+' in 'field list'""/>  <error regexp="MySqlClient\."/> <error regexp="com\.mysql\.jdbc\.exceptions"/><errorregexp="Zend_Db_Statement_Mysqli_Exception"/>|任意扫描方式|存在mysql注入
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