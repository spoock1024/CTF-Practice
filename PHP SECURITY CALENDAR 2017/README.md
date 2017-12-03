## Table of Contents
- [Day 1 - White List](#day-1---white-list)
- [Day 2 - Twig](#day-2---twig)

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