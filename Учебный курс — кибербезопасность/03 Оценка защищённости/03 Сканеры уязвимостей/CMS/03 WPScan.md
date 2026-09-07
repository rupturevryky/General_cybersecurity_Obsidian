---
topic: security-assessment
level: intermediate
status: technical-review-complete
last_reviewed: 2026-08-17
verified_against: https://github.com/wpscanteam/wpscan
---

# WPScan

> [!note] Актуальные требования
> Текущая ветка WPScan требует Ruby 3.3+; в Kali рекомендуется пакетный менеджер. Официальный Docker-образ удобнее для воспроизводимой лаборатории. Том ниже сохраняет обновляемую базу между запусками.

```bash
docker pull wpscanteam/wpscan
docker run --rm -it -v wpscan-db:/wpscan/.cache/wpscan/db wpscanteam/wpscan --update
docker run --rm -it -v wpscan-db:/wpscan/.cache/wpscan/db \
  wpscanteam/wpscan --url https://wordpress.example.test --enumerate u
```

Для данных об известных уязвимостях нужен API-токен. Храните его в переменной `WPSCAN_API_TOKEN` или конфигурации, а не вставляйте в конспект/историю команд.

> [!note] Статус материала
> Исходный конспект сохранён, но команды, версии, зависимости и внешние ссылки необходимо сверять с официальной документацией перед практикой.

## Введение 
WPSCAN предустановлен в kali. Используется для сканирования сайтов **именно** в **CMS WordPress**.
***

## **Начальная конфигурация**

Обновить БД сканера:
```
wpscan --update
```
- `-h` - краткая помощь
- `--hh` - развёрнутая помощь

---

## **Основные**

<li><code>--url</code> <b>-</b> Указать URL. </li>
<li><code>--api-token TOKEN</code> <b>-</b> Использовать token WPSCAN. Его можно получить на сайте  <a>https://wpscan.com/</a>. </li>

Брутфорс логина и пароля:
``` 
... --passwords pass.txt --usernames user.txt
```
Агрессивно (эффективнее) просканировать наличие плагинов:
``` 
... --enumerate ap --plugins-detection aggressive
```
- `ap` - показывает все активные плагины
- `vp` - показывает только уязвимые плагины

<li><code>--cookie-string COOKIE</code> / <code>--cookie-jar FILE-PATH</code> <b>-</b> Смотреть куки и подменять налету. </li>

> Смотреть информацию по уязвимостям в WPVulnDB ([https://wpscan.com/](https://wpscan.com/)) — это сайт, на котором лежит большая БД уязвимостей. На этом сайте вы можете зарегистрироваться, бесплатно получить API и при сканировании WordPress сайтов при указании этой API можно соответственно проверять потенциальные уязвимости и сверять их с БД.

---

## **Дополнительно**

- Куда выводить - на экран терминала или в файл.
- Количество используемых потоков сканирования.

Для тестирования данного сканера можно развернуть уязвимый сервис - [dvwp](https://github.com/vavkamil/dvwp)

---

## **Специфичные**

- `--http-auth login:password` **-** указать, аутентификацию WordPress-а.
- `--user-agent` / `--random-user-agent`**-** Менять вручную user-agentа (`--user-agent`) или менять его рандомно (`--random-user-agent`) — это иногда полезно, когда сайты блочат доступ с определенным user-agent-ом.
- `--proxy protocol://IP:port` **-** сканировать с использованием прокси.

---

## **Пример**

bruteforse авторизации:
``` 
wpscan --url http://10.10.1.1/ --username <USERNAME> --passwords <WORDLIST>
```
сканирование системы:
``` 
wpscan --url http://10.10.1.1/ --enumerate u
```
Пробрутфорсить учётные записи:
```
wpscan --url {URL} -e ap,at,tt,cb,dbe,u1-25,m -P {passList}
```
