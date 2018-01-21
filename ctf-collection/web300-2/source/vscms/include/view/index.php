<?php
if (!defined("Z_ENTRANCE")) {
    header("HTTP/1.0 404 Not Found");
    exit();
}

if (!isset($_SESSION['user']['id'])) {
    header('location: ./index.php?action=view&mod=login&' . time());
    die("Error: You have loged out or your session has expired.");
}

$aObj = new zArticle();
$author = isset($_GET['author']) ? trim($_GET['author']) : '';
if ($author == '') {
    $list = $aObj->getAll();
}
else {
    $list = $aObj->getUserArticles($author);
}

$title = "Home";

require_once(Z_ABSPATH . 'include/view/header.inc.php');
?>
<div class="main-panel panel panel-default">
    <div class="panel-heading">Threads</div>
    <div class="panel-body">
        <table class="table">
            <thead>
            <tr>
                <th style="width:70%;">Title</th>
                <th>Author</th>
            </tr>
            </thead>
            <tbody>
            <?php
            if (is_array($list)) {
                foreach ($list as $item) {
                    ?>
                    <tr>
                        <td><?php echo esc_html($item['title']); ?></td>
                        <td>
                            <a href="./index.php?action=view&mod=index&author=<?php echo esc_html($item['username']); ?>"><?php echo esc_html($item['username']); ?></a>
                        </td>
                    </tr>
                    <?php
                }
            }
            ?>
            </tbody>
        </table>
    </div>
</div>
<?php
require_once(Z_ABSPATH . 'include/view/footer.inc.php');
?>
