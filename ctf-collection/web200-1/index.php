<?php
include "config.php";
echo  "<center><h1>Welcome to my site</h1></center><br>";
$id = $_GET['id']?waf($_GET['id']):1;

$sql = "select * from error_news where id = $id";
$row = mysql_fetch_array(mysql_query($sql));
if (empty($row) or mysql_error()){
    echo "<center>no content detail</center>".mysql_error();
}else{
    echo "<center><table border=1><tr><th>title</th><th>Content</th></tr><tr><td>${row['title']}</td><td>${row['content']}</td></tr></table></center>";
}


function waf($var){
    if(stristr($_SERVER['HTTP_USER_AGENT'],'sqlmap')){
        echo "<center>hacker<center>";
        die();
    }
    $var = preg_replace('/([^a-z]+)(union|from)/i', '$2', $var);
    return $var;
}

highlight_file(__FILE__);