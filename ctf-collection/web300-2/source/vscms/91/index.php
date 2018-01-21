<?php
/**
 * Created by PhpStorm.
 * User: spoock
 * Date: 2018/1/7
 * Time: 16:36
 */

function CurlPost($url, $data, $ssl = false) {
    if (!isset($url) || trim($url) == '' || !isset($data) || empty($data)) {
        return null;
    }

    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);

    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($curl, CURLOPT_TIMEOUT, 5);

    curl_setopt($curl, CURLOPT_POST, 1);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);

    if ($ssl) {
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
    }

    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    $output = curl_exec($curl);
    $errno = curl_errno($curl);
    $errmsg = curl_error($curl);
    curl_close($curl);

    // 记录错误日志
    if ($errno > 0) {
        //echo $errno;
        WriteLog('CURL ERROR, POST, URL:' . $url . ', DATA:' . json_encode($data) . ', CODE:' . $errno . ', MSG:' . $errmsg);
        return null;
    }
    else {
        return $output;
    }
}

function CheckEmpty($obj) {
    if (!isset($obj) || is_null($obj) || $obj == null || $obj === null) {
        return true;
    }
    return false;
}

function CheckInteger($str) {
    if (preg_match("/^[1-9][0-9]*$/", $str)) {
        return true;
    }
    else {
        return false;
    }
}

$params = array("appid" => "yorasQOLqt9Z2VYN", "appsecret" => "uMndXBq3Z0S94UT4oNh8k5epkEU6vVFo", "grant_type" => "client_credentials");

$url = "https://api.chuangcache.com/OAuth/authorize";

$response = CurlPost($url, json_encode($params), true);
var_dump($response);
if (!CheckEmpty($response)) {
    $result = json_decode($response, true);
    var_dump($result);
    if (!CheckEmpty($result) && is_array($result)) {
        if (array_key_exists('status', $result) && $result['status'] === 1) {
            if (array_key_exists('data', $result)) {
                if (isset($result['data']['access_token']) && trim($result['data']['access_token']) != "" && isset($result['data']['expires_in']) && CheckInteger($result['data']['expires_in']) && intval($result['data']['expires_in']) > 360) {
                    $accessToken = $result['data']['access_token'];
                    var_dump($accessToken);
                }
            }
        }
    }
}