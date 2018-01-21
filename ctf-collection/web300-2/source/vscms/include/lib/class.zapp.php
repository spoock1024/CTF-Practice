<?php

/**
 * 初始化程序类
 * @author Ambulong
 *
 */
class zApp
{

    private $DBH = NULL; // OPD数据连接句柄

    public function __construct() {

    }

    /**
     * Initialize the environment and template.
     */
    public function init() {
        $this->initPDO();
        $resetObj = new zReset();
        $resetObj->execute();
        $this->initRouter();
    }

    /**
     * Connect to MySQL server and set the environment.
     */
    public function initPDO() {
        try {
            $this->DBH = new zPDO("mysql:host=" . Z_DB_HOST . ";dbname=" . Z_DB_NAME . ";", Z_DB_USER, Z_DB_PASSWORD, array(PDO::ATTR_PERSISTENT => true, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES '" . Z_DB_CHARSET . "';"));
            $this->DBH->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            $this->DBH->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->DBH->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING);
            $GLOBALS ["z_dbh"] = $this->DBH;
        } catch (Exception $e) {
            header('Content-Type: text/plain; charset=utf-8');
            if (Z_DEBUG)
                die("Error!: " . $e->getMessage());
            else
                die("Connect database error.");
        }
    }

    /**
     * Initialize the router.
     */
    public function initRouter() {
        $router = new zRouter ();
        $router->init();
    }

    public function __destruct() {
        $this->DBH = null;
        if (isset($GLOBALS ["z_dbh"]))
            $GLOBALS ["z_dbh"] = null;
    }

}
