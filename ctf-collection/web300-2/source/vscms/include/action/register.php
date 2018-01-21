<?php

if (!defined("Z_ENTRANCE")) {
    header("HTTP/1.0 404 Not Found");
    exit();
}

if (!z_validate_token()) {
    die("invalid operation.");
}

if (!z_validate_captcha()) {
    die("incorrect captcha.");
}

if (isset($_SESSION['user']['id']))
    die("You have logined your account.");

$username = isset($_POST['username']) ? trim($_POST['username']) : '';
$email = '';
$password = isset($_POST['password']) ? trim($_POST['password']) : '';
$password2 = isset($_POST['password2']) ? trim($_POST['password2']) : '';

if ($username == '' || $password == '' || $password2 == '')
    die('Imcomplete submission.');

if ($password != $password2 || strlen($username) > 50 || strlen($password) > 50)
    die('Error submission.');

$zUserObj = new zUser();

$detail = $zUserObj->getDetailUsr($username);

if (isset($detail['id']))
    die('Duplicate username');

header("Content-type:text/html;charset=utf-8");
if ($zUserObj->add($username, $email, $password)) {
    die('Success');
}
else {
    die('Failed');
}
