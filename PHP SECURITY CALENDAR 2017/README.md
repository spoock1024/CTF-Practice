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