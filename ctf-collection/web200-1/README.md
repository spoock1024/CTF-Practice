这道题目算作是MySQL的小trick吧，做题目的时候可以考虑fuzz一下。这个题目的关键之处在于需要绕过`([^a-z]+)(union|from)/i`

正则表达的意思很简单，在`union`和`from`前面不能仅仅只能包含字母(a-z,A-Z)。
但是在正常的认知中，from前面可以是以下几种：
- 空格(`select * from dual`)
- 括号(`select(1)from dual;`)
- 斜线(`SELECT 1/**/from dual;`)
- 星号(`SELECT 1/*!50000from*/dual;`)

没有出现前面有字母的情况。此时通过fuzz尝试去找一下，发现在from前面可以有`\N`,`\N`在MySQL中就相当于`NULL`。

那么POC就十分的简单了,`id=\Nunion select 1,flag,\Nfrom flag`