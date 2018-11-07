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
PostgreSQL所有可能注入|<error regexp="PostgreSQL.*?ERROR"/>  <error regexp="Warning.*?\Wpg_"/>       <error regexp="valid PostgreSQL result"/> <error regexp="Npgsql\."/> <errorregexp="PG::SyntaxError:"/> <errorregexp="org\.postgresql\.util\.PSQLException"/><error regexp="ERROR:\s\ssyntax error at or near"/>|任意扫描方式|存在PostgreSQL注入
Microsoft SQL Server所有可能注入|        <error regexp="Driver.*? SQL[\-\_\ ]*Server"/>        <error regexp="OLE DB.*? SQL Server"/>        <error regexp="\bSQL Server[^&lt;&quot;]+Driver"/>        <error regexp="Warning.*?(mssql\|sqlsrv)_"/>        <error regexp="\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}"/>        <error regexp="System\.Data\.SqlClient\.SqlException"/>        <error regexp="(?s)Exception.*?\WRoadhouse\.Cms\."/>        <error regexp="Microsoft SQL Native Client error '[0-9a-fA-F]{8}"/>        <error regexp="com\.microsoft\.sqlserver\.jdbc\.SQLServerException"/>        <error regexp="ODBC SQL Server Driver"/>        <error regexp="ODBC Driver \d+ for SQL Server"/>        <error regexp="SQLServer JDBC Driver"/>        <error regexp="macromedia\.jdbc\.sqlserver"/>        <error regexp="com\.jnetdirect\.jsql"/>        <error regexp="SQLSrvException"/>|任意扫描方式|存在Microsoft SQL Server注入
所所有access可能注入| <error regexp="Microsoft Access (\d+ )?Driver"/>        <error regexp="JET Database Engine"/>        <error regexp="Access Database Engine"/>        <error regexp="ODBC Microsoft Access"/>        <error regexp="Syntax error \(missing operator\) in query expression"/>|任意扫描方式|存在access注入
oracle所有可能注入|        <error regexp="\bORA-\d{5}"/>        <error regexp="Oracle error"/>        <error regexp="Oracle.*?Driver"/>        <error regexp="Warning.*?\Woci_"/>        <error regexp="Warning.*?\Wora_"/>        <error regexp="oracle\.jdbc\.driver"/>        <error regexp="quoted string not properly terminated"/>        <error regexp="SQL command not properly ended"/>|任意扫描方式|存在oracle注入
IBM DB2所有可能注入| <error regexp="CLI Driver.*?DB2"/>  <error regexp="DB2 SQL error"/><error regexp="\bdb2_\w+\("/> <error regexp="SQLSTATE.+SQLCODE"/>|任意扫描方式|存在IBM DB2注入
informix所有可能注入|  <error regexp="Exception.*?Informix"/><error regexp="Informix ODBC Driver"/> <error regexp="com\.informix\.jdbc"/> <error regexp="weblogic\.jdbc\.informix"/>|任意扫描方式|存在informix注入
Firebird注入|<error regexp="Dynamic SQL Error"/><error regexp="Warning.*?ibase_"/>|任意扫描方式|存在Firebird注入
sqlite注入|<error regexp="SQLite/JDBCDriver"/><error regexp="SQLite\.Exception"/>        <error regexp="(Microsoft\|System)\.Data\.SQLite\.SQLiteException"/>        <error regexp="Warning.*?sqlite_"/>        <error regexp="Warning.*?SQLite3::"/>        <error regexp="\[SQLITE_ERROR\]"/>        <error regexp="SQLite error \d+:"/>        <error regexp="sqlite3.OperationalError:"/>|任意扫描方式|存在sqlite注入
SAP MaxDB注入|<error regexp="SQL error.*?POS([0-9]+)"/>        <error regexp="Warning.*?maxdb"/>|w3af|存在SAP MaxDB注入
sybase注入|<error regexp="Warning.*?sybase"/>        <error regexp="Sybase message"/>        <error regexp="Sybase.*?Server message"/>        <error regexp="SybSQLException"/>        <error regexp="com\.sybase\.jdbc"/>|awvs|存在sybase注入
Ingres注入|<error regexp="Warning.*?ingres_"/>        <error regexp="Ingres SQLSTATE"/>        <error regexp="Ingres\W.*?Driver"/>|awvs|存在Ingres注入
Frontbase注入|<error regexp="Exception (condition )?\d+\. Transaction rollback"/>        <error regexp="com\.frontbase\.jdbc"/>|awvs|存在Frontbase注入
HSQLDB注入|<error regexp="org\.hsqldb\.jdbc"/><error regexp="Unexpected end of command in statement \["/> <error regexp="Unexpected token.*?in statement \["/>|awvs|存在HSQLDB注入
H2注入|<error regexp="org\.h2\.jdbc"/>|awvs|存在H2注入
flash类型|存在文件如下ZeroClipboard.swf、/zeroclipboard.swf、/swfupload.swf、/swfupload/swfupload.swf、/open-flash-chart.swf、/uploadify.swf、/flowplayer.swf、/Jplayer.swf、/extjs/resources/charts.swf|任意扫描|可能存在flash跨站漏洞
web 编辑器|存在目录 /fckeditor/_samples/default.html 、/ckeditor/samples/ 、/editor/ckeditor/samples/、/ckeditor/samples/sample_posteddata.php、editor/ckeditor/samples/sample_posteddata.php 、fck/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php 、/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellcheckder.php|任意扫描方式|存在web 编辑器
ueditor SSRF|存在目录文件 /ueditor/ueditor.config.js、/ueditor/php/getRemoteImage.php|任意扫描方式|存在ueditor ssrf
目录文件遍历泄漏|/etc/passwd {tag="root:x:"} |任意扫描方式|存在漏洞
目录文件遍历泄漏|/proc/meminfo {tag="MemTotal"}  {status=200}|任意扫描方式|存在漏洞
目录文件遍历泄漏|/etc/profile         {tag="/etc/profile.d/*.sh"}  {status=200}  |任意扫描方式|存在漏洞
目录文件遍历泄漏|/../../../../../../../../../../../../../etc/passwd    {tag="root:x:"} |任意扫描方式|存在漏洞
目录文件遍历泄漏|/../../../../../../../../../../../../../etc/profile   {tag="/etc/profile.d/*.sh"}|任意扫描方式|存在漏洞
目录文件遍历泄漏|//././././././././././././././././././././././././../../../../../../../../etc/profile  {tag="/etc/profile.d/*.sh"} |任意扫描方式|存在漏洞
目录文件遍历泄漏|/aa/../../cc/../../bb/../../dd/../../aa/../../cc/../../bb/../../dd/../../bb/../../dd/../../bb/../../dd/../../bb/../../dd/../../ee/../../etc/profile {status=200}  {tag="/etc/profile.d/*.sh"}|任意扫描方式|存在漏洞
目录文件遍历泄漏|/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/profile {tag="/etc/profile.d/*.sh"}
目录文件遍历泄漏|/javax.faces.resource.../WEB-INF/web.xml.jsf    {status=200}    {type="xml"}    {tag="<?xml"} |任意扫描方式|存在漏洞
|任意扫描方式|存在漏洞
目录文件遍历泄漏|/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd  {tag="root:x:"}  |任意扫描方式|存在漏洞
目录文件遍历泄漏|/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd   {tag="root:x:"} |任意扫描方式|存在漏洞
目录文件遍历泄漏|/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd {tag="root:x:"} |任意扫描方式|存在漏洞
目录文件遍历泄漏|/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd    {tag="root:x:"} |任意扫描方式|存在漏洞
系统服务|/etc/passwd {tag="root:x:"} |任意扫描方式|存在漏洞
系统服务|/etc/passwd {tag="root:x:"} |任意扫描方式|存在漏洞
系统服务|/etc/passwd {tag="root:x:"} |任意扫描方式|存在漏洞
系统服务|/etc/passwd {tag="root:x:"} |任意扫描方式|存在漏洞


