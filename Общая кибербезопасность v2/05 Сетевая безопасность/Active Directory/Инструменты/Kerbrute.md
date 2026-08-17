---
topic: network-security
level: intermediate
status: technical-review-complete
last_reviewed: 2026-08-17
verified_against: https://github.com/ropnop/kerbrute
---

> [!warning] Риск блокировки учётных записей
> Перед `userenum` изучите lockout policy. Используйте официальный релиз, проверьте checksum и начните с `kerbrute --help`.

> [!warning] Разрешённая среда
> Исходный конспект сохранён. В рамках курса команды применяйте только к назначенной цели внешней учебной платформы и в пределах её правил; версии, зависимости и флаги сверяйте с первичной документацией.

### Утилита `kerbrute_linux_amd64`
Инструмент для брутфорса имён пользователей на windows.

``` 
./kerbrute userenum -d {domain} {usernames file} --dc {IP} -v
```
где `userenum` - брутфорс юзернеймов, чтобы узнать валидные

Может быть полезен smbclient: [[Протоколы удалённого доступа#SMBMAP / SMBGET / SMBCLIENT]]
