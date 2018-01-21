<?php
if (! defined ( "Z_ENTRANCE" )) {
	header ( "HTTP/1.0 404 Not Found" );
	exit ();
}

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="zh-CN" lang="zh-CN">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="author" content="Ambulong">
<title><?php echo esc_html((isset($title))?$title:""); ?> - Vulspy</title>
<script src="./js/jquery-1.11.3.min.js"></script>
<script src="./js/jquery-migrate-1.2.1.min.js"></script>
<link href="./css/bootstrap.min.css" rel="stylesheet">
<link href="./css/ie10-viewport-bug-workaround.css" rel="stylesheet">
<!--[if lt IE 9]><script src="./js/ie8-responsive-file-warning.js"></script><![endif]-->
<script src="./js/ie-emulation-modes-warning.js"></script>
<!--[if lt IE 9]>
<script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
<script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
<![endif]-->
<script src="./js/bootstrap.min.js"></script>
<!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
<script src="./js/ie10-viewport-bug-workaround.js"></script>
<link rel="stylesheet" href="./css/custom.css">
<script src="./js/functions.js"></script>
<script src="./upload/custom.js"></script>
<!--[if lt IE 9]>
	<script src="http://css3-mediaqueries-js.googlecode.com/svn/trunk/css3-mediaqueries.js"></script>
<![endif]-->
</head>
<body>
<nav class="navbar navbar-inverse navbar-fixed-top">
  <div class="container-fluid">
    <div class="navbar-header">
      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1" aria-expanded="false">
        <span class="sr-only">Toggle navigation</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="#">#</a>
    </div>
    <div class="collapse navbar-collapse" >   
        <ul class="nav navbar-nav">
        <li><a href="./index.php?action=view&mod=index">Home</a></li>
      </ul>
      <ul class="nav navbar-nav navbar-right">
<?php
if(!isset($_SESSION['user']['id'])){
?>
        <li><a href="./index.php?action=view&mod=login">Login</a></li>
        <li><a href="./index.php?action=view&mod=register">Register</a></li>
<?php 
}else{ 
?>
        <li><a href="#">Hi! <?php echo esc_html($_SESSION['user']['username']);?></a></li>
<?php }?>
      </ul>
    </div>
    
  </div>
</nav>
