---
topic: application-security
level: intermediate
status: source-review-complete
last_reviewed: 2026-08-17
verified_against: https://developer.android.com/security
---
# Теория об Android приложениях


> [!note] Проверка источников завершена
> Базовая линия: Android Developers Security. Исторические примеры сохранены для разбора, но не являются рекомендацией для реальных систем; практику выполняйте только в назначенной лаборатории внешней учебной платформы и в пределах её правил.

> [!note] Статус материала
> Исходный конспект сохранён. Перед учебной практикой необходимо сверить команды, версии инструментов и внешние ссылки с первичными источниками.

![[Учебный курс — кибербезопасность/04 Безопасность приложений/08 Mobile и Android/assets/Pasted image 20250908162823.png]]

### **Этапы работы ART**

![[Учебный курс — кибербезопасность/04 Безопасность приложений/08 Mobile и Android/assets/Pasted image 20250908162857.png]]

1. **Разработка приложения** – Код пишется на **Java** или **Kotlin**.  
2. **Компиляция в байт-код JVM** – Код превращается в `.class` файлы (байт-код Java).  
3. **Преобразование в Dalvik Executable** – `.class` файлы объединяются в `.dex`, оптимизированный для Android.  
4. **AOT-компиляция** – При установке приложение компилируется в машинный код и сохраняется в файле `.oat`.  
5. **Запуск приложения** – ART выполняет уже скомпилированный код, что делает запуск быстрым.  

В отличие от старого Dalvik, который использовал **JIT-компиляцию (Just-In-Time)**, ART изначально применял **AOT-компиляцию (Ahead-Of-Time)**. Начиная с Android 7.0, он стал **гибридным**: **AOT** используется при установке, **JIT** оптимизирует код во время работы, а **PGO (Profile-Guided Optimization)** помогает ускорить выполнение наиболее часто используемых участков кода.

### Файловая структура

Часто во время анализа приложений нам придётся взаимодействовать с устройством при помощи командной строки. Для упрощения восприятия и ускорения поиска необходимой нам информации необходимо понимать так называемый **filesystem layout** — расположение системных и пользовательских папок и файлов в файловой системе.  
  
Если мы захотим увидеть содержимое корневой папки, то увидим примерно следующее:

```
acct        d              init.environ.rc  oem                  sys  
adb_keys    data           linkerconfig     postinstall          system  
apex        data_mirror    lost+found       proc                 system_dlkm 
bin         debug_ramdisk  metadata         product              system_ext  
bugreports  dev            mnt              sdcard               vendor  
cache       etc            odm            second_stage_resources vendor_dlkm 
config      init           odm_dlkm         storage
```

  
Это пример с моего эмулятора, у вас может отличаться. Разберём за что отвечают основные из директорий:

- `/data` хранит изменяемые данные,
- `/system` соответствует `/usr` и хранит систему,
- `/vendor` — аналог `/system`, предназначенный для файлов, специфичных для этой сборки Android, а не входящих в «стандартный» Android,
- `/dev`, как и в «обычном Linux», хранит файлы устройств и другие специальные файлы.
- `/storage/emulated/0/` или `/sdcard/` — виртуальная SD-карта (внутреннее хранилище, доступное пользователю).

---

### Приложение

Архитектура Android построена вокруг приложений. Именно приложения играют ключевую роль в устройстве многих частей системы, на их изоляции основана модель безопасности Android. Так перед исследованием приложения, нам необходимо будет понять, где и как оно хранится в памяти устройства.

**Приложения** – а именно их **APK-файлы**, **файлы ODEX** (скомпилированный Java-код, собранный заранее с помощью AOT) и **ELF-библиотеки** – устанавливаются в следующие директории:

- `/system/app` – для предустановленных приложений, поставляемых с системой.
- `/data/app` – для приложений, устанавливаемых пользователем.

**APK** (англ. **A**ndroid **P**ackage **K**it) — формат архивных исполняемых файлов-приложений для Android и ряда других операционных систем, основанных на Android. Каждое приложение _Android_ скомпилировано и упаковано в один файл, который включает в себя весь код приложения , ресурсы, активы (assets), файл манифеста `AndroidManifest.xml` и нативные библиотеки (`jniLibs`). Файл приложения может иметь любое имя, но расширение должно быть `.APK`, например `myAppFile.apk`.

![[Учебный курс — кибербезопасность/04 Безопасность приложений/08 Mobile и Android/assets/Pasted image 20250908163546.png]]

Каждому предустановленному приложению при создании сборки Android выделяется папка с именем вида:

```
/system/app/Terminal
```

Для устанавливаемых пользователем приложений при установке создаются папки, имена которых начинаются с их имени пакета. Например, приложение YouTube сохраняется в папку с названием вроде:

```
/data/app/com.google.android.youtube-bkJAtUtbTuzvAioW-LEStg==/
```

Но чаще всего мы будем работать с директорией приложения, которая создаётся для хранения изменяемых данных приложения. Она находится по пути `/data/data` и имеет вид обратного доменного имени, что соответствует названию **уникального пакета приложения** (package name):
```
emu64x:/data/data # ls  
android  
...
com.android.chrome  
...
com.android.externalstorage  
com.android.htmlviewer  
com.android.imsserviceentitlement  
com.android.inputdevices  
com.android.intentresolver  
...
com.google.android.apps.docs  
com.google.android.apps.maps  
com.google.android.apps.messaging  
com.google.android.apps.nexuslauncher  
com.google.android.apps.photos  
com.google.android.apps.restore  
com.google.android.apps.wallpaper  
com.google.android.apps.wallpaper.nexus  
com.google.android.apps.wellbeing  
com.google.android.apps.youtube.music  
...
com.google.android.bluetooth  
com.google.android.calendar  
...
com.google.android.webview  
com.google.android.wifi.dialog  
com.google.android.wifi.resources  
com.google.android.youtube  
com.google.mainline.adservices  
com.google.mainline.telemetry
```

В этой папке приложение может хранить:

|Папка|Содержимое|
|---|---|
|`/cache/`|Временные файлы, которые можно удалить без последствий.|
|`/code_cache/`|Кэшированные версии кода (например, JIT-компиляция ART).|
|`/databases/`|SQLite-базы данных (`.db`, `.db-shm`, `.db-wal`).|
|`/files/`|Хранимые файлы (например, изображения, JSON, кэш API).|
|`/shared_prefs/`|Настройки приложения в `.xml` (используется `SharedPreferences`).|
|`/lib/`|Нативные библиотеки (`.so`), если приложение использует C/C++.|
|`/app_webview/`|Данные WebView (если приложение использует встроенный браузер).|
|`/no_backup/`|Для хранения данных, которые не должны резервироваться (бэкапироваться) автоматически через сервисы.|

Например:

```
emu64x:/data/data/com.google.android.youtube # ls   
cache  code_cache  databases  files  no_backup  shared_prefs
```

Про инструмент `ADB` при помощи которого я получил доступ к командной строке устройства, мы так же поговрим чуть позже.

![[Учебный курс — кибербезопасность/04 Безопасность приложений/08 Mobile и Android/assets/Pasted image 20250908163855.png]]
