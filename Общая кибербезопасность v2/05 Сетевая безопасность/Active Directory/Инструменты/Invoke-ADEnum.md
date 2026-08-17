---
topic: network-security
level: intermediate
status: technical-review-complete
last_reviewed: 2026-08-17
verified_against: https://github.com/Leo4j/Invoke-ADEnum
---

> [!warning] Не исполняйте код прямо из сети
> Скачайте конкретный релиз или коммит, проверьте файл и импортируйте локально в разрешённой лаборатории.

> [!warning] Разрешённая среда
> Исходный конспект сохранён. В рамках курса команды применяйте только к назначенной цели внешней учебной платформы и в пределах её правил; версии, зависимости и флаги сверяйте с первичной документацией.

## Введение 

**Invoke-ADEnum** - это инструмент перечисления, предназначенный для автоматизации процесса сбора информации из среды **Active Directory**. С помощью **Invoke-ADEnum** можно перечислить различные аспекты **Active Directory**, включая леса, домены, трасты, контроллеры домена, пользователей, группы, компьютеры, общие ресурсы, подсети, ACL, OUs, GPO и т. д. Одной из особенностей **Invoke-ADEnum** является способность генерировать отчет об аудите **Active Directory** в формате HTML. При выполнении оценок безопасности, аудита соответствия или общих задач по перечислению **Active Directory** отчет предоставит подробный обзор инфраструктуры **Active Directory** в удобном для навигации виде, а также рекомендации по устранению обнаруженных ошибок. ПРИМЕЧАНИЕ: Щелкнув по заголовкам таблиц, вы можете сгенерировать и загрузить CSV-версию результатов. Кроме того, у вас есть возможность экспортировать весь HTML-отчет в формат XLSX, нажав на "Аудит Active Directory" в верхней части страницы. Экспорт XLSX будет включать отдельный лист для каждой таблицы результатов. Пример HTML_отчета, сгенерированного Invoke-ADEnum, вы можете найти здесь: https://leo4j.github.io/Invoke-ADEnum/

---

## Использование

**Установка:**
``` shell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Leo4j/Invoke-ADEnum/main/Invoke-ADEnum.ps1' -OutFile '.\Invoke-ADEnum.ps1'
Get-FileHash '.\Invoke-ADEnum.ps1' -Algorithm SHA256
# После ручной проверки содержимого:
Import-Module '.\Invoke-ADEnum.ps1'
```

Страница справки: 
```
Invoke-ADEnum -Help
``` 
Сначала проверьте цели и убедитесь, что вы прицелены на неё:
``` 
Invoke-ADEnum -TargetsOnly
```

Рекомендуемое покрытие:
```
Invoke-ADEnum -Recommended -SprayEmptyPasswords -FindLocalAdminAccess -RBCD -UserCreatedObjects -AllDescriptions
```

Укажите простой домен для перечисления и DC для привязки к нему:
```
Invoke-ADEnum -Domain contoso.local -Server DC01.contoso.local
```

Исключение доменов, не входящих в сферу охвата:
``` 
Invoke-ADEnum -Exclude "contoso.local,domain.local"
```

Сохраните данные сбора на диск, затем загрузите их с диска и пропустите сбор при следующем запуске (Расположение: `c:\Users\Public\Documents\Invoke-ADEnum`)
```
Invoke-ADEnum -SaveToDisk
```
```
Invoke-ADEnum -LoadFromDisk
```

Полное покрытие (может занять много времени в зависимости от размера домена):
```
Invoke-ADEnum -AllEnum -Force
```
