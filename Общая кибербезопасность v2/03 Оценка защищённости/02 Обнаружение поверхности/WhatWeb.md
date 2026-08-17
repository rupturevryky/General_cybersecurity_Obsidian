---
topic: security-assessment
level: intermediate
status: technical-review-complete
last_reviewed: 2026-08-17
verified_against: https://github.com/urbanadventurer/WhatWeb
---

> [!note] Проверка установки и синтаксиса

```bash
whatweb --version
whatweb --help
whatweb https://example.test
whatweb http://192.0.2.10:8080
```

Фигурные скобки в старых примерах ниже обозначают заполнитель, а не часть команды. Используйте только адреса из разрешённого scope.

> [!note] Статус материала
> Исходный конспект сохранён, но команды, версии, зависимости и внешние ссылки необходимо сверять с официальной документацией перед практикой.

Сканирует web-ресурсы.

узнать службы, работающие на web-сайте:
```
whatweb {URL}
```
или
```
whatweb {IP}:{port}
```
