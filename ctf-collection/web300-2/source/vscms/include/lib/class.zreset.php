<?php

class zReset {

    private $dbh = NULL;
    private $tmpfile = 'C:/phpStudy/WWW/vscms/tmp/dbapp_ctf_time5654386ftr.txt';
    private $lasttime = null;

    public function __construct() {
        $this->tmpfile = 'C:/phpStudy/WWW/vscms/tmp/dbapp_crf_time'.md5(Z_ABSPATH).'.txt';
        $this->dbh = $GLOBALS ['z_dbh'];
        if(!file_exists($this->tmpfile))
            file_put_contents ($this->tmpfile, time());
        $this->lasttime = file_get_contents($this->tmpfile);
    }
    
    function execute(){
        $this->resetAdmin();
        if(time() - $this->lasttime >= 1200){ //清空上传数据周期
            $this->resetDBUsers();
            $this->resetTime();
        }
    }


    //重置时间
    function resetTime(){
        file_put_contents ($this->tmpfile, time());
    }

    //重置数据库内users表
    function resetDBUsers() {
        global $table_prefix;
        try {
            $sth = $this->dbh->prepare("delete from {$table_prefix}users where groupid != 1");
            $sth->execute();
            if (!($sth->rowCount() > 0)) {
                return FALSE;
            }
            return TRUE;
        } catch (PDOExecption $e) {
            throw new Exception($e->getMessage());
        }
    }
    
    function resetAdmin(){
        global $table_prefix;
        $time = get_time();
        try {
            $sth = $this->dbh->prepare("update {$table_prefix}users set time = '1972-01-01 01:01:01' where CAST(time AS CHAR(20)) = '0000-00-00 00:00:00'");
            $sth->execute();
            $sth = $this->dbh->prepare("update {$table_prefix}users set password = '43207bd789f4ef3ea861c3c668f299c7', time = '{$time}' where groupid = 1 and ABS(timestampdiff(SECOND, '{$time}', time)) > 180");
            $sth->execute();
            if (!($sth->rowCount() > 0)) {
                return FALSE;
            }
            return TRUE;
        } catch (PDOExecption $e) {
            throw new Exception($e->getMessage());
        }
    }
    
    //清空指定文件夹
    function delFile($dirName) {
        if (file_exists($dirName) && $handle = opendir($dirName)) {
            while (false !== ($item = readdir($handle))) {
                if ($item != "." && $item != "..") {
                    if (file_exists($dirName . '/' . $item) && is_dir($dirName . '/' . $item)) {
                        $this->delFile($dirName . '/' . $item);
                    } else {
                        if (unlink($dirName . '/' . $item)) {
                            return true;
                        }
                    }
                }
            }
            closedir($handle);
        }
    }

}
