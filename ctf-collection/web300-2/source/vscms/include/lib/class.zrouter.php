<?php

/**
 * 程序路由处理类
 * @author ambulong
 *
 */
class zRouter
{

    private $action = array("view", "action");
    private $module = array("index", "captcha", "login", "register");
    private $action_val;
    private $module_val;

    /**
     * 获取并简单处理URL
     */
    public function __construct() {
        if (!isset($_GET['action']) || !isset($_GET['mod'])) {
            header('location: ./index.php?action=view&mod=index&' . time());
            exit;
        }
        $this->action_val = isset($_GET['action']) ? $_GET['action'] : "view";
        $this->module_val = isset($_GET['mod']) ? $_GET['mod'] : "index";
    }

    /**
     * 初始化路由
     */
    public function init() {
        if (!in_array($this->action_val, $this->action)) {
            header("HTTP/1.0 404 Not Found");
            header('Content-Type: text/plain; charset=utf-8');
            if (Z_DEBUG)
                die("Action \"" . $this->action_val . "\" is invalid");
            else
                exit("404 Not Found");
        }
        if (!in_array($this->module_val, $this->module)) {
            header("HTTP/1.0 404 Not Found");
            header('Content-Type: text/plain; charset=utf-8');
            if (Z_DEBUG)
                die("Module \"" . $this->module_val . "\" is invalid");
            else
                exit("404 Not Found");
        }

        $filename = Z_ABSPATH . "include/" . $this->action_val . "/" . $this->module_val . ".php";

        if (is_readable($filename)) {
            require_once($filename);
        }
        else {
            header('Content-Type: text/plain; charset=utf-8');
            if (Z_DEBUG)
                die("ERROR: File ./" . "include/" . $this->action_val . "/" . $this->module_val . ".php" . " is unreadable.");
            else
                exit("404 Not Found");
        }
    }

}
