
<?php
/**
 * Created by PhpStorm.
 * User: xyz
 * Date: 2017/7/4
 * Time: 10:15
 */
include('config.php');
include('session.class.php');

$session = new session($mysqli);

if($_POST['name']){
    $_SESSION['name'] = $_POST['name'];
    $_SESSION['score'] = 10;
    $session->update_session();
}
?>
<style>
    p{ margin:0 auto}
</style>
<h1 style="text-align:center">一起猜数字</h1>
<div class="login-box" id="login-id" align="center">
    <div>
        <form id="login-form-id" class="login-form">
            <p>
                <label>用户拥有初始积分10分，系统随机生成数字1-6，用户猜对数字加1分，猜错数字扣1分，用户积满100分即可得到系统赠送的flag。</label>
            </p>
            <br>
            <p>
                <label>用户姓名:<?php echo $_SESSION['name'];?></label>
                &nbsp;&nbsp;&nbsp;
                <label>已有积分:<?php echo $_SESSION['score'];?></label>
            </p>
        </form>
    </div>
    <br>
<?php
if(!empty($_SESSION['name']) && ($_SESSION['name'] != 'guest') && ($_SESSION['score'] > 0) ){
    if($_SESSION['score'] >= 100){
        echo '恭喜你获得flag: ' . $flag;
    }
    if(!empty($_POST['choose'])) {
        $right = random();
        if($_POST['choose'] === $right){
            $_SESSION['score'] += 1;
            echo '恭喜你猜对了~    <a href="index.php">继续游戏</a>';
        }
        else{
            $_SESSION['score'] -= 1;
            echo '很遗憾你猜错了~    <a href="index.php">继续游戏</a>';
        }
        $session->update_session();
    }
    else{
        ?>
        <form action="index.php" method="post">
            请作出你的选择：
            <select  name="choose">
                <option value="1" selected="selected">1</option>
                <option value="2" >2</option>
                <option value="3">3</option>
                <option value="4">4</option>
                <option value="5" >5</option>
                <option value="6">6</option>
            </select>
            <input type="submit" value="Go" />
        </form>

        <?php

    }
}
else{
    ?>
<div class="login-box" id="login-id" align="center">
<form action="index.php" method="post">
    <Label align="center">请输入姓名进行游戏:</Label> <input type="text" name="name" align="center" />
  <input type="submit" value="Submit" />
</form>
</div>

<?php }
?>
