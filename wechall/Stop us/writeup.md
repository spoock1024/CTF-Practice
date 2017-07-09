### Problem description
Noother has created a business to sell .xyz domains for some bucks.
Your job is to find a hole in the script that would allow purchases without paying for it.
You can test the script here.
To help you in debugging, you can take a look at the sourcecode, also as highlighted version.
There is a second file involved for the purchase table: noothtable.php, also as hightlighted version, but you probably don't need it.

Good luck!

### Code
```PHP
<?php
/**
 * noothworx proudly presents a secure shop for domain selling!
 */
# Disable output buffering
if (ob_get_level() > 0) ob_end_clean();
apache_setenv('no-gzip', 1);
ini_set('zlib.output_compression', 0);

# The core and init
chdir('../../../');
$_GET['mo'] = 'WeChall';
$_GET['me'] = 'Challenge';
$cwd = getcwd();
require_once 'protected/config.php';
require_once '../gwf3.class.php';
$gwf = new GWF3($cwd, array(
    'website_init' => true,
    'autoload_modules' => true,
    'load_module' => true,
    'get_user' => true,
    'do_logging' => true,
    'blocking' => false,
    'no_session' => false,
    'store_last_url' => true,
    'ignore_user_abort' => false,
));

# Need noothtable!
require_once 'challenge/noother/stop_us/noothtable.php';

# Get challenge
define('GWF_PAGE_TITLE', 'Stop us');
if (false === ($chall = WC_Challenge::getByTitle(GWF_PAGE_TITLE)))
{
    $chall = WC_Challenge::dummyChallenge(GWF_PAGE_TITLE, 3, 'challenge/noother/stop_us/index.php', false);
}

$price = 10.00; # Price for a domain.
$user = GWF_User::getStaticOrGuest();
$sid = GWF_Session::getSession()->getID();
noothtable::initNoothworks($sid); # init domain stuff.
?>
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <title>[WeChall] noother-Domain.com</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="Content-Language" content="en" />
    <meta name="robots" content="index, follow" />
    <meta name="keywords" content="wechall, challenge, stopus, stop us, stop_us" />
    <meta name="description" content="noother-domain.com is a fictional service selling .xyz domains. It is a hacking challenge on wechall." />
    <link rel="shortcut icon" href="/favicon.ico" />
    <link rel="stylesheet" type="text/css" href="/tpl/default/css/gwf3.css?v=9" />
    <link rel="stylesheet" type="text/css" href="/tpl/wc4/css/wechall4.css?v=9a" />
</head>
<body>
<h1><a href="nootherdomain.php">noother-domains.com</a> (powered by <a href="/challenge/noother/stop_us/index.php">WeChall</a>)</h1>

<?php
if (Common::getGetString('load') === 'balance')
{
    if (noother_timeout($sid) === false)
    {
        nooth_message('Checking your credit card ...');
        nooth_message('Uploading $10.00 ...');
        # +10 money and +1 funding
        noothtable::increaseMoney($sid, 10);
        nooth_message(sprintf('Your account balance is now $%.02f.<br/>Thank you for using noother-domains.com!', noothtable::getMoney($sid)));
    }
}

if (Common::getGetString('purchase') === 'domain')
{
    if (noother_timeout($sid) === false)
    {
        nooth_message('Checking your balance ...');
        nooth_message(sprintf('Your balance is $%.02f ...', noothtable::getMoney($sid)));
        if (noothtable::getMoney($sid) >= $price)
        {
            nooth_message('Balance ok!');

            # TODO: Do checks more checks!
            nooth_message('Checking availability of your domain ...');
            nooth_message('Domain is available ...');

            # +1 domain
            if (false === noothtable::purchaseDomain($sid))
            {
                die('Hacking attempt!');
            }
            nooth_message('Purchasing ...');
            nooth_message('Domain purchased.');

            # -$10.00
            nooth_message('Reducing your balance ...');
            noothtable::reduceMoney($sid, $price);
            nooth_message('Thank you for your purchase!');

            # Done!
            nooth_message('Purchased!');

            # Something weird? Oo
            if (noothtable::getFundings($sid) < noothtable::getDomains($sid))
            {
                GWF_Module::loadModuleDB('Forum', true, true);
                # Get here, hacker!
                $chall->onChallengeSolved(GWF_Session::getUserID());
            }
            nooth_message('Thank you for using noother-domains.com!');
        }
        else
        {
            nooth_message('Insufficient funds!');
        }
    }
}

# The page!
?>
<div>
    <div>Username: <?php echo $user->displayUsername(); ?></div>
    <div>Balance: <?php printf('$%.02f', noothtable::getMoney($sid)); ?></div>
    <div>Domains: <?php echo noothtable::getDomains($sid); ?></div>
    <div><a href="nootherdomain.php?load=balance">Upload money</a>(<?php echo noothtable::getFundings($sid); ?>)</div>
    <div><a href="nootherdomain.php?purchase=domain">Purchase domain</a></div>
</div>
</body>
<?php
########################
### Helper functions ###
########################
function noother_timeout($sid)
{
    $wait = noothtable::checkTimeout($sid, time());
    if ($wait >= 0)
    {
        nooth_message(sprintf('Please wait %s until the next transaction.', GWF_Time::humanDuration(45)));
        return true;
    }
    return false;
}

function nooth_message($message, $sleep=2)
{
    echo sprintf('<div>%s</div>', $message).PHP_EOL;
    flush();
    sleep($sleep);
}
?>
```

### solution
这是一道很有趣的题目，这道题目完全是没有输入的。当时要求可以任意地进行购买domain

#### 条件竞争？
起初以为是一个条件竞争的题目，发现每次需要相隔45s才能够提交，同时我也没有找到条件竞争的入口，那么说明就不是条件竞争。

#### 如何中断？
通过观察代码发现，在进行购买时的逻辑是：
```PHP
# +1 domain
if (false === noothtable::purchaseDomain($sid))
{
    die('Hacking attempt!');
}
nooth_message('Purchasing ...');
nooth_message('Domain purchased.');

# -$10.00
nooth_message('Reducing your balance ...');
noothtable::reduceMoney($sid, $price);
nooth_message('Thank you for your purchase!');
```
先通过增加Domain的数量，然后在减少金钱。如果可以在增加Domain之后，PHP停止处理下面的请求，这样就可以不付钱就可以购买domain了。那么在客户端如何停止服务器端的处理呢？在网上也有人提出相同的问题，[Need help to exploit php script vulnerability of a challenge](https://security.stackexchange.com/questions/123110/need-help-to-exploit-php-script-vulnerability-of-a-challenge)

#### ignore_user_abort
发现函数`ignore_user_abort`,
>设置客户端断开连接时是否中断脚本的执行,PHP 以命令行脚本执行时，当脚本终端结束，脚本不会被立即中止，除非设置 value 为 TRUE，否则脚本输出任意字符时会被中止.

观察代码我们发现设置`ignore_user_abort`设置的是fasle，所以我们就可以利用这个设置。
>在PHP尝试发送信息到客户端之前，不会检测到用户是否已中断连接。 仅使用 echo 语句不能确保信息已发送，参见 flush() 函数。

我们看到在题目中大量使用了flush()函数，通过flush函数就可以检测我客户端的中断请求。

#### final
只要在页面中出现`Domain purchased.`，按下`ESC`或者是停止请求，就可以进行购买了

