<?php
if (!defined("Z_ENTRANCE")) {
    header("HTTP/1.0 404 Not Found");
    exit();
}

$title = "Register";

if (isset($_SESSION['user']['id']))
    die("You have logined your account.");

require_once(Z_ABSPATH . 'include/view/header.inc.php');
?>

<div class="panel panel-default" style="width: 25em;margin: 8em auto;">
    <div class="panel-heading">
        <span>Register</span>
    </div>
    <div class="panel-body">
        <form action="./index.php?action=action&mod=register" method="post">
            <div class="form-group">
                <label for="input-user">Username</label>
                <input type="text" class="form-control" name="username" id="input-user">
            </div>
            <div class="form-group">
                <label for="input-password">Password</label>
                <input type="password" class="form-control" name="password" id="input-password">
            </div>
            <div class="form-group">
                <label for="input-password2">Repeat Password</label>
                <input type="password" class="form-control" name="password2" id="input-password2">
            </div>
            <div class="form-group">
                <label for="input-captcha">Captcha</label>
                <div style="height: 3em;">
                    <input style="width:6em;" type="text" class="pull-left form-control" name="captcha" id="input-captcha">
                    <img class="pull-left" title="refresh" src="./index.php?action=view&mod=captcha" align="absbottom" onclick="this.src = './index.php?action=view&mod=captcha&' + Math.random();"></img>
                </div>
            </div>
            <hr>
            <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
            <button type="submit" class="btn btn-primary btn-block">Submit</button>
        </form>
        <br><a href="./index.php?action=view&mod=login">&LeftArrow;Login</a>
    </div>
</div>

<?php
require_once(Z_ABSPATH . 'include/view/footer.inc.php');
?>
