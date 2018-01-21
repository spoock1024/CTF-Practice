<?php
if (! defined ( "Z_ENTRANCE" )) {
	header ( "HTTP/1.0 404 Not Found" );
	exit ();
}

$zCaptchaObj = new zCaptcha(80,30,4);
 
$zCaptchaObj->showImg();

$_SESSION['user']['captcha'] = $zCaptchaObj->getCaptcha();