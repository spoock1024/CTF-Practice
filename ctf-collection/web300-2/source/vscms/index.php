<?php
define("Z_ENTRANCE", true);

define('Z_ABSPATH', dirname(__FILE__) . '/');

require_once(Z_ABSPATH . 'config.php');
require_once(Z_ABSPATH . 'include/functions.php');
require_once(Z_ABSPATH . 'include/autoload.php');
z_debug_mode();
//z_check_php_mysql ();
date_default_timezone_set(Z_TIMEZONE);
if (!is_session_started())
    session_start();
if (!isset($_SESSION['token']))
    $_SESSION['token'] = get_salt(32);
$appObj = new zApp();
$appObj->init();
