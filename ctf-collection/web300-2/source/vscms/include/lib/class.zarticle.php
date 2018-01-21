<?php

/**
 * @author ambulong zeng.ambulong@gmail.com
 */
class zArticle {
	private $dbh = NULL;
	public $id = NULL;

	public function __construct() {
		$this->dbh = $GLOBALS ['z_dbh'];
	}
	
	public function getAll() {
		global $table_prefix;
		try {
		    $sql = "SELECT * FROM {$table_prefix}articles order by id desc";
		    $sth = $this->dbh->query($sql);
		    $result = $sth->fetchAll(PDO::FETCH_ASSOC);
		    return $result;
		} catch (PDOExecption $e) {
		    throw new Exception($e->getMessage());
		}
	}
	
	public function getUserArticles($username) {
		global $table_prefix;
		$username = trim($username);
		$status = isset($_GET['status'])?trim($_GET['status']):1;
		try {
		    $uObj = new zUser;
		    $udetail = $uObj->getDetailUsr($username);
		    if(!isset($udetail['id'])){
		    	return false;
		    }
		    $additional = z_db_prepare("and `username`= %s ", $username);
		    $sql = z_db_prepare("SELECT * FROM {$table_prefix}articles where `status`=%d ".$additional, $status);
		    $sth = $this->dbh->query($sql);
		    $result = $sth->fetchAll(PDO::FETCH_ASSOC);
		    return $result;
		} catch (PDOExecption $e) {
		    throw new Exception($e->getMessage());
		}
	}
}
