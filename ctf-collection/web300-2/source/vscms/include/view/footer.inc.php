<?php
if (! defined ( "Z_ENTRANCE" )) {
	header ( "HTTP/1.0 404 Not Found" );
	exit ();
}
?>
<div class="hidden" id="token"><?php echo $_SESSION['token'];?></div>
</body>
</html>
