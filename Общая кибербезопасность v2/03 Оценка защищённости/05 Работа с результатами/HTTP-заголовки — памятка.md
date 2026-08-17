---
topic: security-assessment
level: intermediate
status: source-review-complete
last_reviewed: 2026-08-17
verified_against: https://owasp.org/www-project-secure-headers/
---

> [!note] Проверка источников завершена
> Базовая линия: OWASP Secure Headers. Исторические payload-примеры ниже сохранены для разбора, но не считаются рекомендацией для реальных систем; практику выполняйте только в назначенной лаборатории внешней учебной платформы и в пределах её правил.

> [!note] Статус материала
> Исходный конспект сохранён, но команды, версии, зависимости и внешние ссылки необходимо сверять с официальной документацией перед практикой.

OWASP cheatsheets: https://cheatsheetseries.owasp.org/index.html

## Заголовки 

Указать серверу, какой у пользователя адрес/откуда пользователь переходит:
1. `X-Forwarded-For`: domain или IP
2. `True-Client-IP`: domain или IP
3. `Referer`: http:/***/
4. `X-WAP-Profile`: https://***/wap.xml
