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
$password = isset($_POST['password']) ? trim($_POST['password']) : '';

if ($username == '' || $password == '')
    die('Imcomplete submission.');

$zUserObj = new zUser();

$detail = $zUserObj->getDetailUsr($username);

if (!isset($detail['id']))
    die('Incorrect username or password.');
if (!$zUserObj->auth($detail['id'], $password))
    die('Incorrect username or password.');

$zUserObj->login($detail['id'], $username);
header('location: ./index.php');