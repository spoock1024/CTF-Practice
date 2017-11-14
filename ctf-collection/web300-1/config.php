<?php
/**
 * Created by PhpStorm.
 * User: xyz
 * Date: 2017/7/4
 * Time: 10:39
 */
error_reporting(E_ERROR | E_WARNING | E_PARSE);

$DBHOST = 'localhost';
$DBUSER = 'root';
$DBPASS = 'root';
$DBNAME = 'test';
$flag = 'flag{123456}';

$mysqli = new mysqli($DBHOST, $DBUSER, $DBPASS, $DBNAME);

foreach ($_GET as $key => $value ) {
    $_GET[$key] = daddslashes($value);
}

foreach ($_POST as $key => $value ) {
    $_POST[$key] = daddslashes($value);
}

foreach ($_COOKIE as $key => $value ) {
    $_COOKIE[$key] = daddslashes($value);
}

foreach ($_SERVER as $key => $value ) {
    $_SERVER[$key] = addslashes($value);
}

function daddslashes($string) {
    if(!get_magic_quotes_gpc()) {
        if(is_array($string)) {
            foreach($string as $key => $val) {
                $string[$key] = daddslashes($val);
            }
        } else {
            $string = addslashes($string);
        }
    }
    return $string;
}

function random(){
    $chars  = '123456';
    $chars  = str_shuffle($chars);
    return substr($chars, 0, 1);
}