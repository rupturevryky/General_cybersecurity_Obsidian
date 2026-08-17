---
topic: application-security
level: intermediate
status: technical-review-complete
last_reviewed: 2026-08-17
verified_against:
  - https://developer.android.com/tools/adb
  - https://developer.android.com/studio/run/emulator-commandline
  - https://github.com/skylot/jadx
  - https://apktool.org/docs/cli-parameters/
  - https://mas.owasp.org/MASTG/
---

> [!note] Техническая проверка завершена
> Синтаксис сверен с Android SDK Platform Tools, Android Emulator, JADX, Apktool 3.x и OWASP MASTG. Перед выполнением всё равно проверьте версии через `adb version`, `jadx --version` и `apktool --version`.

## Среда курса

- Актуальные Android SDK Platform Tools (`adb`) — из официального Android SDK.
- Android-экземпляр и тестовый APK, если их предоставляет назначенная внешняя платформа.
- JADX и Apktool — для статического разбора; MobSF — как вспомогательный анализатор, если он входит в задание.
- OWASP MASVS/MASTG — как методика и критерии проверки.
- Перехватывающий proxy — только если это предусмотрено заданием и его сертификат устанавливается в выданную среду.

Не устанавливайте APK из случайных каталогов и не используйте рабочий смартфон. Курс не требует самостоятельного развёртывания Android-стенда.

> [!warning] Граница применения
> Команды ниже применяются только к APK, пакету и Android-экземпляру, явно выданным платформой. Не переносите идентификаторы и техники на другие приложения или устройства.

# Инструментарий

![[10 Справочники/Каталог инструментов#Декомпиляторы для программ на Java и под Android|Инструментарий для анализа Android-приложений]]

## ADB — Android Debug Bridge

ADB взаимодействует с подключённым устройством или эмулятором. Если доступно несколько целей, обязательно укажите предоставленный платформой serial через `-s`.

```bash
adb devices -l
adb -s <SERIAL> shell
adb -s <SERIAL> install <LAB_APP.apk>
adb -s <SERIAL> logcat
adb -s <SERIAL> push <LOCAL_FILE> <REMOTE_PATH>
```

- `adb shell` открывает обычную оболочку и сам по себе не требует root.
- `adb root` перезапускает `adbd` с повышенными правами только на поддерживающих это отладочных сборках или эмуляторах; на production-сборках команда обычно отклоняется.
- `adb install` устанавливает только APK, предоставленный заданием. При нескольких устройствах используйте `-d`, `-e` или `-s <SERIAL>`.

### Компоненты приложения

Сначала изучите `AndroidManifest.xml` и убедитесь, что компонент действительно экспортирован и входит в scope задания.

```bash
adb -s <SERIAL> shell am start -W -n <PACKAGE>/<ACTIVITY>
adb -s <SERIAL> shell am startservice -n <PACKAGE>/<SERVICE>
adb -s <SERIAL> shell content query --uri 'content://<AUTHORITY>/<PATH>'
```

- Правильная команда запуска сервиса — `am startservice`, а не `startservis`.
- На современных версиях Android запуск фонового сервиса может быть ограничен политикой платформы; фактическое поведение зависит от версии Android и состояния приложения.
- `content query` обращается к доступному content provider. Наличие URI не доказывает уязвимость: отдельно проверяются экспортирование, разрешения, обработка аргументов и наблюдаемое влияние.

### Локальный Android Emulator

Команда `emulator -avd <AVD_NAME> -writable-system` существует, но не входит в практический маршрут этого курса. Она создаёт временную записываемую копию системного образа, после запуска которой для записи в `system` требуется `adb remount`. Используйте её только вне курса в отдельно разрешённом сценарии.

## JADX

JADX преобразует DEX-код в читаемое Java-представление и декодирует manifest и ресурсы. Декомпиляция может быть неполной, поэтому результат нужно сопоставлять со smali и поведением приложения.

```bash
jadx --version
jadx -d <OUTPUT_DIR> <LAB_APP.apk>
jadx-gui <LAB_APP.apk>
```

## Apktool

Apktool декодирует ресурсы и дизассемблирует DEX в smali.

```bash
apktool --version
apktool d <LAB_APP.apk> -o <OUTPUT_DIR>
```

Короткая форма `d` означает `decode`. Параметр `-f` разрешает удалить уже существующий выходной каталог и потому не должен добавляться автоматически.
