原文链接：https://www.ripstech.com/php-security-calendar-2017/

[中文版](README_CN.md)

## Table of Contents
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
Can you spot the vulnerability?
```PHP
class Challenge {
    const UPLOAD_DIRECTORY = './solutions/';
    private $file;
    private $whitelist;

    public function __construct($file) {
        $this->file = $file;
        $this->whitelist = range(1, 24);
    }

    public function __destruct() {
        if (in_array($this->file['name'], $this->whitelist)) {
            move_uploaded_file(
                $this->file['tmp'],
                self::UPLOAD_DIRECTORY . $this->file['name']
            );
        }
    }
}

$challenge = new Challenge($_FILES['solution']);
```

**solution**

The challenge contains an arbitrary file upload vulnerability in line 13. The operation in_array() is used in line 12 to check if the file name is a number. However, it is type-unsafe because the third parameter is not set to 'true'. Hence, PHP will try to type-cast the file name to an integer value when comparing it to the array $whitelist (line 8). As a result it is possible to bypass the whitelist by prepending a value in the range of 1 and 24 to the file name, for example "5backdoor.php". The uploaded PHP file then leads to code execution on the web server.

[Back to TOC](#table-of-contents)

## Day 2 - Twig
Can you spot the vulnerability?
```PHP
// composer require "twig/twig"
require 'vendor/autoload.php';

class Template {
    private $twig;

    public function __construct() {
        $indexTemplate = '<img ' .
            'src="https://loremflickr.com/320/240">' .
            '<a href="{{link|escape}}">Next slide »</a>';

        // Default twig setup, simulate loading
        // index.html file from disk
        $loader = new Twig\Loader\ArrayLoader([
            'index.html' => $indexTemplate
        ]);
        $this->twig = new Twig\Environment($loader);
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

**solution**

The challenge contains a cross-site scripting vulnerability in line 26. There are two filters that try to assure that the link that is passed to the `<a>` tag is a genuine URL. First, the `filter_var()` function in line 22 checks if it is a valid URL. Then, Twig's template escaping is used in line 10 that avoids breaking out of the `href` attribute.

The vulnerability can still be exploited with the following URL: `?nextSlide=javascript://comment%250aalert(1)`.
The payload does not involve any markup characters that would be affected by Twig's escaping. At the same time, it is a valid URL for `filter_var()`. We used a JavaScript protocol handler, followed by a JavaScript comment introduced with `//` and then the actual JS payload follows on a newline. When the link is clicked, the JavaScript payload is executed in the browser of the victim.

[Back to TOC](#table-of-contents)

## Day 3 - Snow Flake
Can you spot the vulnerability?
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

**solution**

In this code are two security bugs. A file inclusion vulnerability is triggered by the call of `class_exists()` in line 8. Here, the existance of a user supplied class name is checked. This automatically invokes the custom autoloader in line 1 in case the class name is unknown which will try to include unknown classes. An attacker can abuse this file inclusion by using a path traversal attack. The lookup for the class name `../../../../etc/passwd` will leak the passwd file. The attack only works until version 5.3 of PHP.

But there is a second bug that also works in recent PHP versions. In line 9, the class name is used for a new object instantiation. The first argument of its constructor is under the attackers control as well. Arbitrary constructors of the PHP code base can be called. Even if the code itself does not contain a vulnerable constructor, PHP's built-in class `SimpleXMLElement` can be used for an XXE attack that also leads to the exposure of files. A real world example of this exploit can be found in our [blog post](https://blog.ripstech.com/2017/shopware-php-object-instantiation-to-blind-xxe/).

[Back to TOC](#table-of-contents)

## Day 4 - False Beard
Can you spot the vulnerability?
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

**solution**

This challenge suffers from an XML injection vulnerability in line 13. An attacker can manipulate the XML structure and hence bypass the authentication. There is an attempt to prevent exploitation in lines 8 and 9 by searching for angle brackets but the check can be bypassed with a specifically crafted payload. The bug in this code is the automatic casting of variables in PHP. The PHP built-in function `strpos()` returns the numeric position of the looked up character. This can be `0` if the first character is the one searched for. The 0 is then type-casted to a boolean `false` for the `if` comparison which renders the overall constraint to true. A possible payload could look like `user=<"><injected-tag%20property="&pass=<injected-tag>`.

[Back to TOC](#table-of-contents)

## Day 5 - Postcard
Can you spot the vulnerability?
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

**solution**

This challenge suffers from a command execution vulnerability in line 31. The fifth parameter of mail, in this case the variable `$_POST['from']`, is appended to the sendmail command that is executed to send out the email. It is not possible to execute arbitrary commands here but it is possible to append arbitrary new parameters to sendmail. This can be abused to create a PHP backdoor in the web directory through the log files of sendmail.

There are 2 insufficient protections in place that try to prevent successful exploitation. The method `sanitize()` first checks in line 3 if the e-mail address is valid. However, not all characters that are necessary to exploit the security issue in `mail()` are forbidden by this filter. It allows the usage of escaped whitespaces nested in double quotes. In line 7 the e-mail address gets sanitized with `escapeshellarg()`. This would be sufficient if PHP would not escape the fifth parameter internally with `escapeshellcmd()`. Since it does escape the parameter again, the `escapeshellcmd()` allows an attacker to break out of the `escapeshellarg()`. More information, details, and a PoC can be found in our blog post ["Why mail() is dangerous in PHP"](https://blog.ripstech.com/2017/why-mail-is-dangerous-in-php/).

[Back to TOC](#table-of-contents)

## Day 6 - Frost Pattern
Can you spot the vulnerability?
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

**solution**

This challenge contains a file delete vulnerability. The bug causing this issue is a non-escaped hyphen character (`-`) in the regular expression that is used in the `preg_replace()` call in line 21. If the hyphen is not escaped, it is used as a range indicator, leading to a replacement of any character that is not a-z or an ASCII character in the range between dot (`46`) and underscore (`95`). Thus dot and slash can be used for directory traversal and (almost) arbitrary files can be deleted, for example with the query parameters `action=delete&data=../../config.php`.

[Back to TOC](#table-of-contents)

## Day 7 - Bells
Can you spot the vulnerability?
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

**solution**

This challenge suffers from a connection string injection vulnerability in line 4. It occurs because of the `parse_str()` call in line 21 that behaves very similar to register globals. Query parameters from the referrer are extracted to variables in the current scope, thus we can control the global variable `$config` inside of `getUser()` in lines 5 to 8. To exploit this vulnerability we can connect to our own MySQL server and return arbitrary values for username, for example with the referrer `http://host/?config[dbhost]=10.0.0.5&config[dbuser]=root&config[dbpass]=root&config[dbname]=malicious&id=1`

[Back to TOC](#table-of-contents)

## Day 8 - Candle
Can you spot the vulnerability?
```PHP
header("Content-Type: text/plain");

function complexStrtolower($regex, $value) {
    return preg_replace(
        '/(' . $regex . ')/ei',
        'strtolower("\\1")',
        $value
    );
}

foreach ($_GET as $regex => $value) {
    echo complexStrtolower($regex, $value) . "\n";
}
```

**solution**

This challenge contains a code injection vulnerability in line 4. Prior to PHP 7 the operation `preg_replace()` contained an eval modifier, short `e`. If the modifier is set, the second parameter (replacement) is treated as PHP code. We do not have a direct injection point into the second parameter but we can control the value of `\\1`, as it references the matched regular expression. It is not possible to escape out of the `strtolower()` call but since the referenced value is inside of double quotes, we can use PHP’s curly syntax to inject other function calls. An attack could look like this: `/?.*={${phpinfo()}}`.

[Back to TOC](#table-of-contents)

## Day 9 - Rabbit
Can you spot the vulnerability?
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

**solution**

This challenge contains a file inclusion vulnerability that can allow an attacker to execute arbitrary code on the server or to leak sensitive files. The bug is in the sanitization function in line 18. The replacement of the `../` string is not executed recursively. This allows the attacker to simply use the character sequence `....//` or `..././` that after replacement will end in `../` again. Thus, changing the path to the included language file via path traversal is possible. For example, the system's passwd file can be leaked by setting the following payload in the Accept-Language HTTP request header: `.//....//....//etc/passwd`.

[Back to TOC](#table-of-contents)

## Day 10 - Anticipation
Can you spot the vulnerability?
```PHP
extract($_POST);

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

**solution**

This challenge contains a code injection vulnerability in line 12 that can be used by an attacker to execute arbitrary PHP code on the web server. The operation `assert()` evaluates PHP code and it contains user input. In line 1, all POST parameters are instantiated as global variables by PHP's built-in function `extract()`. This can lead to severe problems itself but in this challenge it is only used for a variety of sources. It enables the attacker to set the `$pi` variable directly via POST Parameter. In line 8 there is a check to verify if the input is numeric and if not the user is redirected to an error page via the `goAway()` function. However, after the redirect in line 5 the PHP script continues running because there is no `exit()` call. Thus, user provided PHP code in the `pi` parameter is always executed, e.g. `pi=phpinfo()`.

[Back to TOC](#table-of-contents)

## Day 11 - Pumpkin Pie
Can you spot the vulnerability?
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
        && !preg_match('/O:\d:\{/', $data)) {
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

**solution**

This challenge contains an PHP object injection vulnerability. In line 13 an attacker is able to pass user input into the `unserialize()` function by altering his cookie data. There are two checks in line 11 and 12 that try to prevent the deserialization of objects. The first check can be easily circumvented, for example by injecting an object into an array, leading to a payload string beginning with `a:1:` instead of `O:`. The second check can be bypassed by abusing PHP's flexible serialization syntax. It is possible to use the syntax `O:+1:` to bypass this regex. Finally, this means an attacker can inject an object of class `Template` into the application. After the serialized form is deserialized and the Template object is instantiated, its destructor is called when the script terminates (line 31). Now, the attacker controlled properties `cacheFile` and `template` of the injected object are used to write to a file in line 21. Thus, the attacker can create arbitraries files on the file system, for example a PHP shell in the document root: `a:1:{i:0;O:%2b8:"Template":2:{s:9:"cacheFile";s:14:"/var/www/a.php";s:8:"template";s:16:"<?php%20phpinfo();";}}` More information about this attack can be found [in our blog posts](https://blog.ripstech.com/tags/php-object-injection/).

[Back to TOC](#table-of-contents)

## Day 12 - String Lights
Can you spot the vulnerability?
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

**solution**

There is a cross-site scripting vulnerability in line 13. This bug depends on the fact that the keys of the `$_GET` array (the GET parameter names) are not sufficiently sanitized in the code. Both the keys and the sanitized GET values are passed to the `href` attribute of the `<a>` tag as a concatenated string. The sanitizer `htmlentities()` is used, however, single quotes are not affected by default by this built-in function. Hence, an attacker is able to perform an XSS attack against the user, for example using the following query parameter that breaks the href attribute and appends an eventhandler with JavaScript code: `/?a'onclick%3dalert(1)%2f%2f=c`. Note that the payload is within the parameter name, not the parameter value.

[Back to TOC](#table-of-contents)

## Day 13 - Turkey Baster
Can you spot the vulnerability?
```PHP
class LoginManager {
    private $em;
    private $user;
    private $password;

    public function __construct($user, $password) {
        $this->em = DoctrineManager::getEntityManager();
        $this->user = $user;
        $this->password = $password;
    }

    public function isValid() {
        $user = $this->sanitizeInput($this->user);
        $pass = $this->sanitizeInput($this->password);
        
        $queryBuilder = $this->em->createQueryBuilder()
            ->select("COUNT(p)")
            ->from("User", "u")
            ->where("user = '$user' AND password = '$pass'");
        $query = $queryBuilder->getQuery();
        return boolval($query->getSingleScalarResult());
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

**solution**

Today's challenge contains a DQL (Doctrine Query Language) injection vulnerability in line 19. A DQL injection is similar to a SQL injection but more limited, nonetheless the `where()` method of Doctrine is vulnerable. In line 13 and 14 sanitization is added to the input, however, the `sanitizeInput()` method has a bug. First, it uses `addslashes()` for escaping relevant characters by adding a backslash \ infront of them. In this case if we pass a \ as input, it get escaped to \\. But then, the `substr()` function is used to truncate the escaped string. This enables an attacker to send a string that is long enough that the escaped backslash is cut off and we are left with a single \ at the end of the string. This will then break the WHERE statement and allows the injection of own DQL syntax, for example the condition `OR 1=1` that is always true and bypasses the authentication: `user=1234567890123456789\&passwd=%20OR%201=1-`. The resulting WHERE statement will look like `user = '1234567890123456789\' AND password = ' OR 1=1-'` in DQL. Note how the backslash confuses the quotes and allows to inject DQL into the password value. The resulting query does not look valid because of the trailing slash. Fortunately, Doctrine closes the last single quote on its own, so the resulting query looks like `OR 1=1-''`.

To avoid DQL injections always use bound parameters for dynamic conditions. Never try to secure a DQL query with `addslashes()` or similar functions. Additionally, the password should be stored hashed in the database, for example in the BCrypt format.

[Back to TOC](#table-of-contents)

## Day 14 - Snowman
Can you spot the vulnerability?
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

**solution**

This class is vulnerable to directory traversal because of mass assignment. The constructor can be used to set arbitrary class attributes (line 11). By overwriting the attribute `$id` you gain control over the first parameter of `file_put_contents()` in line 16. With the help of `../` it is possible to target arbitrary files on the system that are writable, for example it can be used to create a PHP shell in the document root. The values that are send to the class are incremented in line 11 and thus an integer after the operation is done. The incrementation happens after the assignment though, so the class attribute contains the original value of `$count`.

To avoid this security issue be vary careful when using reflection based on user input to set variables. It is recommended to implement a white-list verfication that contains the names of all variables that can be modified. A real world example of a vulnerability that is caused by mass assignment can be found [in our blog](https://blog.ripstech.com/2016/the-state-of-wordpress-security/#podlove-publisher).

[Back to TOC](#table-of-contents)

## Day 15 - Sleigh Ride
Can you spot the vulnerability?
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

**solution**

This challenge contains an open redirect vulnerability in line 6. The code takes the input from the super global `$_SERVER['PHP_SELF']` and splits it at the slash character (line 10). Then the last part is taken and used to build the new URL that is passed into the `header()` function. An attacker is able to inject his own URL by using url-encoded characters that are decoded in line 5. A possible payload could look like `/index.php/http:%252f%252fwww.domain.com?redirect=1`.

This bug allows an attacker to redirect the user from the original site to a site of the attackers will. The attacker then could do phishing, for example he could present a forged login screen to grab the credentials of the user for the original site.

[Back to TOC](#table-of-contents)

## Day 16 - Poem
Can you spot the vulnerability?
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

**solution**

This challenge contains two bugs that can be used together to inject data into the open FTP connection. The first bug is the usage of `$_REQUEST` in line 9 while only sanitizing `$_GET` and `$_POST` in lines 14 to 16. `$_REQUEST` is the combination of `$_GET`, `$_POST`, and `$_COOKIE` but it is only a copy of the values, not a reference. Therefore the sanitization of `$_GET`, `$_POST`, and `$_COOKIE` alone is not sufficient. A real world example of a vulnerability that is caused by a similar confusion can be found [in our blog](https://blog.ripstech.com/2016/the-state-of-wordpress-security/#all-in-one-wp-security-firewall).

The second bug is the usage of the type-unsafe comparison `==` instead of `===` in line 25. This enables an attacker to inject and execute new commands in the existing connection, for example a delete command with the query string `?mode=1%0a%0dDELETE%20test.file`.

[Back to TOC](#table-of-contents)

## Day 17 - Mistletoe
Can you spot the vulnerability?
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

**solution**

This challenge is supposed to be a fixed version of day 13 but it introduces new vulnerabilities instead. The author tried to fix the DQL injection by applying `addslashes()` without `substr()` on the user name, and by hashing the password in line 13 using `md5()`. Besides the fact that md5 should not be used to hash passwords and that password hashes should not be compared this way, the second parameter is set to true. This returns the hash in binary format. The binary hash can contain ASCII characters that are interpreted by Doctrine. In this case an attacker could use the value `128` as the password, resulting in `v�an���l���q��\` as hash. With the backslash at the end the single quote gets escaped leading to an injection. A possible payload could be `?user=%20OR%201=1-&passwd=128`.

To avoid DQL injections always use bound parameters for dynamic conditions. Never try to secure a DQL query with `addslashes()` or similar functions. Additionally, the password should be stored in a secure hashing format, for example BCrypt.

[Back to TOC](#table-of-contents)

## Day 18 - Sign
Can you spot the vulnerability?
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

**solution**

This challenge contains a bug in the usage of the `openssl_verify()` function in line 5 that leads to an authentication bypass in line 7. The function has three return values: `1` if the signature is correct, `0` if the signature verification failed, and `-1` if there was an error while performing the verification. So if an attacker generates a valid signature for the data using another algorithm than the one `pub_key.pem` is using, the `openssl_verify()` function returns `-1` which is casted to `true` automatically. To avoid this problem use the type-safe comparison `===` to validate the return value of `openssl_verify()`, or consider using a different [library for cryptography](https://paragonie.com/blog/2015/11/choosing-right-cryptography-library-for-your-php-project-guide).

[Back to TOC](#table-of-contents)

## Day 19 - Birch
Can you spot the vulnerability?
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

**solution**

The `ImageViewer` class is prone to remote command execution through the `size` parameter in line 17. The `preg_replace()` call will purge almost any non-digit characters. This is not sufficient though because the function `stripcslashes()` will not only strip slashes but it will also replace C literal escape sequences with their actual byte representation. The backslash character is untouched by the `preg_replace()` call allowing an attacker to inject an octal byte escape sequence similar to `0\073\163\154\145\145\160\0405\073`. The `stripcslashes()` function will evaluate this input to `0;sleep 5;` which is concatenated into the system command and finally executed in the attackers favor.

[Back to TOC](#table-of-contents)

## Day 20 - Stocking
Can you spot the vulnerability?
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
        return '<img src="' . $path . '" width="100"/>';
    }
}

echo (new ImageLoader())->getResult($_GET['img']);
```

**solution**

This challenge contains a server-side request forgery vulnerability. It allows an attacker to perform requests on behalf of the attacked web server. Thus, servers can be reached that would otherwise be not reachable for an external attacker. For example, this can be abused to perform a port scan and to grab banners (e.g., version of the server) on an internal network that the web server is part of. The exploitable parts are the usage of `file_get_contents()` with unfiltered user input in line 14 and the printing of the error message to the user in line 23. An attacker can request an internal URI like `?img=http://internal:22` and would get a response such as `failed to open stream: HTTP request failed! SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2` if OpenSSH is running. Information like this can be used to prepare further attacks. Another popular exploit scenario is the retrieval of sensitive AWS credentials when attacking an AWS cloud instance. Besides that, `filter_var()` also accepts `file://` URLs, enabling an attacker to load local files.

[Back to TOC](#table-of-contents)

## Day 21 - Gift Wrap
Can you spot the vulnerability?
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

**solution**

This challenge contains a command injection vulnerability in line 33. The developer declared `strict_types=1` in line 1 to ensure the the type hint in the validate function in line 7 throws a `TypeError` exception if a non-int is passed to the class. Even with strict types enabled there is an bug with the usage of `array_walk()` which ignores the strict typing and uses the default weak typing of PHP instead. An attacker can therefore just append a command to the last parameter that is executed in the system call. A possible payload could look like `?p[1]=1&p[2]=2;%20ls%20-la`.

[Back to TOC](#table-of-contents)

## Day 22 - Chimney
Can you spot the vulnerability?
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

**solution**

The code snippet suffers from 4 vulnerabilities. First, the type-unsafe comparison operator is used in line 12 to compare the hashed password to a string. The string has the form of the scientific notation and as a result it is interpreted as “zero to the power of X”, which is zero. So if we are able to generate a zero-string for the hashed user input as well, the check compares zero to zero and succeeds. This hashes are called “Magic Hashes” and a Google search reveals that the MD5 hash of the value `240610708` results in the desired properties. The code snippet calculates the MD5 hash of the password twice though, so it is not possible to directly submit the value. Instead you have to exploit the second vulnerability: the first hash is calculated on the server side but stored in a cookie on the client side. Thus the value `240610708` simply has to be directly injected into the password cookie.

There are two more vulnerabilities but they are not relevant for this challenge. First, the comparison of the hashes is vulnerable to timing attacks. To prevent this issue, the PHP function `hash_equals()` should be used for comparison. Second, the PHP function `md5()` is used to hash the password. The MD5 algorithm is considered broken and it was not designed for password hashing. Instead a secure password hashing algorithm like BCrypt should be used. It should be noted that passwords also should not be hard coded but separated into a configuration file.

[Back to TOC](#table-of-contents)

## Day 23 - Cookies
Can you spot the vulnerability?
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

**solution**

The `LDAPAuthenticator` class is prone to an LDAP injection in line 24. By injecting special characters into the username it is possible to alternate the result set of the LDAP query. Although the `ldap_escape()` function is used to sanitize the input in lines 19 and 20, a wrong flag has been passed to the sanitize-calls resulting in insufficient/incorrect sanitization. Therefore, in this particular example, the LDAP injection results in an unauthenticated adversary bypassing the authentication mechanism by injecting the asterisk-wildcard `*` character as username and password to successfully login as an arbitrary user.

[Back to TOC](#table-of-contents)

## Day 24 - Nutcracker
Can you spot the vulnerability?
```PHP
@$GLOBALS=$GLOBALS{next}=next($GLOBALS{'GLOBALS'})
[$GLOBALS['next']['next']=next($GLOBALS)['GLOBALS']]
[$next['GLOBALS']=next($GLOBALS[GLOBALS]['GLOBALS'])
[$next['next']]][$next['GLOBALS']=next($next['GLOBALS'])]
[$GLOBALS[next]['next']($GLOBALS['next']{'GLOBALS'})]=
next(neXt(${'next'}['next']));
```

**solution**

This challenge consists of a code snippet that was created by one of our team members for the Hack.lu CTF Tournament. It makes heavy use of the `next()` function and the `$GLOBALS` array. The `next()` function moves the internal array pointer up by one. Combined with the `$GLOBALS` array this allows us to execute arbitrary code.

The payload has to be split up into 2 segments: First, a PHP function to execute, passed in via `$_COOKIE[‘GLOBALS’]`. Second, parameters for the injected function, passed in via the file type of a sent file with the same name as the called PHP function. A more detailed write-up of the solution can be found [here](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/next-global-backdoor).

[Back to TOC](#table-of-contents)
