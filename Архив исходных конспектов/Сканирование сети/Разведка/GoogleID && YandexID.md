Инструкция по идентификации пользователей Google и Яндекс для слежки.

---

# GoogleID

Стоит учитывать, что у абсолютно любой почты может быть GoogleID, так как Google старается следить за всеми.

Узнать GoogleID и аватар пользователя по адресу электронной почты можно следующим способом:

1. Заходим в настройки (https://calendar.google.com/)
   
   ![[Pasted image 20250418112534.png]]
   
2. Добавить календарь >> Подписаться на календарь
   
   ![[Pasted image 20250418113322.png]]

3. Узнаём аватар пользователя (значение "`s`" позволяет менять размер):
   
   ![[Pasted image 20250418114441.png]]

   ![[Pasted image 20250418114227.png]]
   
\[2] Переходим в "Контакты". Щелкаем правой кнопкой мыши и выбираем "Просмотр кода страницы" (https://contacts.google.com/)
1. Через поиск находим нужный контакт

   ![[Pasted image 20250418115515.png]]

2. Переходим в карточку пользователя

   ![[Pasted image 20250418120533.png]]

3. Открываем исходный код (`crtl+U`)
4. Находим в нём саму почту, она будет на самом дне страницы:

   ![[Pasted image 20250418122918.png]]
   
   5. Видим на 2м месте предыдущего массива и 9м месте следующего массива сам GoogleID:
   
   ![[Pasted image 20250418123104.png]]

---

# YandexID

1. Перейдите в Яндекс Коллекции по ссылке `yandex.ru/collections/user/******`, где `******` - это никнейм пользователя (`никнейм@yandex.ru` (`никнейм@yandex.ru`))
2. Щелкаем правой кнопкой мыши и выбираем "Просмотр кода страницы"
3. Находим в коде пункт "cover_info". Перед ней будет пользовательский :ID (:12345678)

---

# Получение данных

> Google:
- `google.com/maps/contrib/*GoogleID*` - Google карты, отзывы
- `get.google.com/albumarchive/*GoogleID*` - публичный Google фотоальбом 
- `drive.google.com/drive/search?q=owner:*GoogleMail*` - публичный Google Drive
- `plus.google.com/*GoogleID*` - 

> Yandex:
- `yandex.ru/collections/user/*nickname*/` - Yandex Коллекции
- `n.maps.yandex.ru/#/users/*YandexID*` - Yandex Карты
- `music.yandex.ru/user/*nickname*/` - Yandex Музыка