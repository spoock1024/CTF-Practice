<?php
/**
 * Author: ambulong zeng.ambulong@gmail.com
 */

class zUser
{

    private $dbh = NULL;
    public $id = NULL;

    public function __construct() {
        $this->dbh = $GLOBALS ['z_dbh'];
    }

    function add($username, $email, $password) {
        global $table_prefix;
        $hash = md5($password);
        $username = trim($username);
        $email = trim($email);
        $time = get_time();
        try {
            $sql = z_db_prepare("INSERT INTO {$table_prefix}users(`username`,`email`,`password`,`time`) VALUES(%s, %s, %s, %s)", $username, $email, $hash, $time);
            $sth = $this->dbh->query($sql);
            if (!($sth->rowCount() > 0)) {
                return FALSE;
            }
            return TRUE;
        } catch (PDOExecption $e) {
            throw new Exception($e->getMessage());
        }
    }

    function resetToken($id) {
        return True;
    }

    function auth($id, $password) {
        $id = intval($id);
        $detail = $this->getDetailID($id);
        $hash = $detail['password'];
        if (md5(md5($password)) == md5($hash))
            return TRUE;
        else
            return FALSE;
    }

    public function isExistUser($username) {
        global $table_prefix;
        $username = strtolower(trim($username));
        try {
            $sql = z_db_prepare("SELECT count(*) FROM {$table_prefix}users WHERE `username` = %s ", $username);
            $sth = $this->dbh->query($sql);
            $row = $sth->fetch();
            if ($row [0] > 0) {
                return TRUE;
            }
            else {
                return FALSE;
            }
        } catch (PDOExecption $e) {
            throw new Exception($e->getMessage());
        }
    }

    public function isExistMail($mail) {
        return True;
    }

    public function getDetailID($id) {
        global $table_prefix;
        $id = intval($id);
        try {
            $sql = z_db_prepare("SELECT * FROM {$table_prefix}users WHERE `id` = %d", $id);
            $sth = $this->dbh->query($sql);
            $result = $sth->fetch(PDO::FETCH_ASSOC);
            return $result;
        } catch (PDOExecption $e) {
            throw new Exception($e->getMessage());
        }
    }

    public function getDetailUsr($username) {
        global $table_prefix;
        $username = trim($username);
        try {
            $sql = z_db_prepare("SELECT * FROM {$table_prefix}users WHERE `username` = %s", $username);
            $sth = $this->dbh->query($sql);
            $result = $sth->fetch(PDO::FETCH_ASSOC);
            return $result;
        } catch (PDOExecption $e) {
            throw new Exception($e->getMessage());
        }
    }

    public function getAll() {
        global $table_prefix;
        try {
            $sql = "SELECT * FROM {$table_prefix}users order by id desc";
            $sth = $this->dbh->query($sql);
            $result = $sth->fetchAll(PDO::FETCH_ASSOC);
            return $result;
        } catch (PDOExecption $e) {
            throw new Exception($e->getMessage());
        }
    }

    public function login($id, $username) {
        $_SESSION["user"]['id'] = $id;
        $_SESSION["user"]['username'] = $username;
        return TRUE;
    }

    public function logout() {
        unset($_SESSION["user"]);
        return TRUE;
    }

}
