<?php

/**
 * Is session started
 * @return bool
 */
function is_session_started() {
    if (php_sapi_name() !== 'cli') {
        if (version_compare(phpversion(), '5.4.0', '>=')) {
            return session_status() === PHP_SESSION_ACTIVE ? TRUE : FALSE;
        }
        else {
            return session_id() === '' ? FALSE : TRUE;
        }
    }
    return FALSE;
}

/**
 * Get current time
 *
 * @return String
 */
function get_time() {
    return date('Y-m-d H:i:s');
}

/**
 * Get date
 *
 * @return String
 */
function get_date() {
    return date('Y-m-d');
}

/**
 * Is str in formats like json
 *
 * @param String $string
 * @return bool
 */
function is_json($string) {
    json_decode($string, true);
    return (json_last_error() == JSON_ERROR_NONE);
}

/**
 * Htmlspecialchars
 *
 * @param String $string
 * @return array or string
 */
function esc_html($string) {
    if (is_array($string)) {
        foreach ($string as $key => $val) {
            $string [$key] = esc_html($val);
        }
    }
    else {
        //var_dump($string);
        $string = htmlspecialchars($string);
    }
    return $string;
}

function z_addslashes($string) {
    if (is_array($string)) {
        foreach ($string as $key => $val) {
            $string [$key] = z_addslashes($val);
        }
    }
    else {
        //var_dump($string);
        $string = addslashes($string);
    }
    return $string;
}

/**
 * Get current page URL
 *
 * @return string
 */
function get_url() {
    $ssl = (!empty($_SERVER ['HTTPS']) && $_SERVER ['HTTPS'] == 'on') ? true : false;
    $sp = strtolower($_SERVER ['SERVER_PROTOCOL']);
    $protocol = substr($sp, 0, strpos($sp, '/')) . (($ssl) ? 's' : '');
    $port = $_SERVER ['SERVER_PORT'];
    $port = ((!$ssl && $port == '80') || ($ssl && $port == '443')) ? '' : ':' . $port;
    $host = isset($_SERVER ['HTTP_X_FORWARDED_HOST']) ? $_SERVER ['HTTP_X_FORWARDED_HOST'] : isset($_SERVER ['HTTP_HOST']) ? $_SERVER ['HTTP_HOST'] : $_SERVER ['SERVER_NAME'];
    return $protocol . '://' . $host . $port . $_SERVER ['REQUEST_URI'];
}

/**
 * 获取域名
 *
 * @param unknown $referer
 * @return unknown
 */
function get_url_domain($referer) {
    preg_match("/^(http:\/\/)?([^\/]+)/i", $referer, $matches);
    $domain = isset($matches [2]) ? $matches [2] : "unknow";
    return $domain;
}

/**
 * URL跳转
 *
 * @param unknown $url
 */
function gotourl($url) {
    header("Location: {$url}");
}

/**
 * 获取浏览用户信息，HTTP头，IP等
 */
function get_user_info() {
    return array("IP" => get_ip(), "TIME" => get_time(), "HTTP_ACCEPT" => isset($_SERVER ["HTTP_ACCEPT"]) ? $_SERVER ["HTTP_ACCEPT"] : "", "HTTP_REFERER" => isset($_SERVER ["HTTP_REFERER"]) ? $_SERVER ["HTTP_REFERER"] : "", "HTTP_USER_AGENT" => isset($_SERVER ["HTTP_USER_AGENT"]) ? $_SERVER ["HTTP_USER_AGENT"] : "");
}

function get_salt($length = 8) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $salt = '';
    for ($i = 0; $i < $length; $i++) {
        $salt .= $chars [mt_rand(0, strlen($chars) - 1)];
    }
    return $salt;
}

function getTimestamp() {
    return time();
}

/**
 * Check the required php version and the MySQL extension
 *
 * @access private
 */
function z_check_php_mysql() {
    $required_php_version = "5.3.9";
    $php_version = phpversion();
    if (version_compare($required_php_version, $php_version) > 0) {
        header('Content-Type: text/plain; charset=utf-8');
        die("Your server is running PHP version {$php_version} but the application requires at least {$required_php_version}.");
    }

    if (!extension_loaded('PDO')) {
        header('Content-Type: text/plain; charset=utf-8');
        die("Your PHP installation appears to be missing the MySQL extension.");
    }
}

/**
 * Set PHP error reporting based on debug settings.
 *
 * @access private
 */
function z_debug_mode() {
    if (Z_DEBUG) {
        error_reporting(E_ALL);
    }
    else {
        error_reporting(0);
    }
}

function json_resp($status, $msg, $data = array()) {
    header('Content-Type: text/json; charset=utf-8');
    $resp = array("status" => $status, "msg" => $msg, "data" => $data);
    echo json_encode($resp);
    exit;
}

function z_validate_token() {
    if (!isset($_REQUEST ['token'])) {
        return FALSE;
    }
    $token = isset($_REQUEST ['token']) ? $_REQUEST ['token'] : "";
    if (md5($_SESSION ["token"]) == md5($token)) {
        return TRUE;
    }
    return FALSE;
}

function z_validate_captcha() {
    $ccaptcha = isset($_SESSION['user']['captcha']) ? $_SESSION['user']['captcha'] : '';
    if ($ccaptcha == '')
        return FALSE;
    unset($_SESSION['user']['captcha']);
    if (!isset($_REQUEST ['captcha'])) {
        return FALSE;
    }
    $captcha = isset($_REQUEST ['captcha']) ? $_REQUEST ['captcha'] : "";
    if (md5(strtolower($ccaptcha)) == md5(strtolower($captcha)))
        return TRUE;
    else
        return false;
}

function z_logout() {
    unset($_SESSION);
    session_unset();
    session_destroy();
}

function cutstr_html($string) {
    $string = strip_tags($string);
    $string = trim($string);
    $string = str_replace("\t", "", $string);
    $string = str_replace("\r\n", "", $string);
    $string = str_replace("\r", "", $string);
    $string = str_replace("\n", "", $string);
    $string = str_replace(" ", "", $string);
    $string = str_replace("&nbsp;", "", $string);
    return trim($string);
}

function text_html($string) {
    $string = strip_tags($string);
    $string = str_replace("\t", "&nbsp;&nbsp;&nbsp;&nbsp;", $string);
    $string = str_replace("\r\n", "<br>", $string);
    $string = str_replace("\r", "", $string);
    $string = str_replace("\n", "<br>", $string);
    $string = str_replace(" ", "&nbsp;", $string);
    return trim($string);
}

function get_sign($str) {
    $arr = str_split($str);
    sort($arr, SORT_STRING);
    return md5(implode('', $arr));
}


function z_to_zhtime($time) {
    return date("Y年m月d日 H时i分s秒", strtotime($time));
}

function z_to_zhdate($time) {
    return date("m月d日", strtotime($time));
}

function z_to_zhdateY($time) {
    return date("Y年m月d日", strtotime($time));
}

function z_to_zhdatestr($time) {
    if (strtotime($time) >= date('Y-m-d'))
        return '今天';
    elseif (strtotime($time) >= date('Y-m-d', strtotime('-1 day')))
        return '昨天';
    elseif (strtotime($time) >= date('Y-m-d', strtotime('-2 day')))
        return '前天';
    else
        return date("m月d日", strtotime($time));
}

function z_islogin() {
    if (isset($_SESSION['user']) && @$_SESSION['user']['id'] > 0)
        return true;
    else
        return false;
}

function z_chkIdcard($idcard) {

    // 只能是18位  
    if (strlen($idcard) != 18) {
        return false;
    }

    // 取出本体码  
    $idcard_base = substr($idcard, 0, 17);

    // 取出校验码  
    $verify_code = substr($idcard, 17, 1);

    // 加权因子  
    $factor = array(7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2);

    // 校验码对应值  
    $verify_code_list = array('1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2');

    // 根据前17位计算校验码  
    $total = 0;
    for ($i = 0; $i < 17; $i++) {
        $total += substr($idcard_base, $i, 1) * $factor[$i];
    }

    // 取模  
    $mod = $total % 11;

    // 比较校验码  
    if ($verify_code == $verify_code_list[$mod]) {
        return true;
    }
    else {
        return false;
    }
}

function z_getAgeByID($id) {

    //过了这年的生日才算多了1周岁
    if (empty($id))
        return '';
    $date = strtotime(substr($id, 6, 8));
    //获得出生年月日的时间戳
    $today = strtotime('today');
    //获得今日的时间戳
    $diff = floor(($today - $date) / 86400 / 365);
    //得到两个日期相差的大体年数
    //strtotime加上这个年数后得到那日的时间戳后与今日的时间戳相比
    $age = strtotime(substr($id, 6, 8) . ' +' . $diff . 'years') > $today ? ($diff + 1) : $diff;

    return $age;
}

function z_totext($str) {
    $t = str_replace("\n", "<br>", esc_html($str));
    $t = str_replace(" ", "&nbsp;", $t);
    return $t;
}

function z_db_prepare($query, $args) {
    if (is_null($query))
        return;
    // This is not meant to be foolproof -- but it will catch obviously incorrect usage.
    if (strpos($query, '%') === false) {
        die('The query argument of %s must have a placeholder.');
    }
    $args = func_get_args();
    array_shift($args);
    // If args were passed as an array (as in vsprintf), move them up
    if (isset($args[0]) && is_array($args[0]))
        $args = $args[0];
    $query = str_replace("'%s'", '%s', $query); // in case someone mistakenly already singlequoted it
    $query = str_replace('"%s"', '%s', $query); // doublequote unquoting
    $query = preg_replace('|(?<!%)%f|', '%F', $query); // Force floats to be locale unaware
    $query = preg_replace('|(?<!%)%s|', "'%s'", $query); // quote the strings, avoiding escaped strings like %%s
    array_walk($args, 'myaddslashes');
    return @vsprintf($query, $args);
}

function myaddslashes(&$v, $key) {
    $v = addslashes($v);
}
