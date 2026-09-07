# Журналы, аудит и Sysmon

> [!abstract] Результат
> Ученик находит события по времени и Provider, понимает зависимость телеметрии от политики аудита и строит временную цепочку, а не вывод по одному Event ID.

## Windows Event Log

Журналы организованы в каналы. Базовые:

- `System` — ОС, драйверы и службы;
- `Application` — приложения;
- `Security` — события политики аудита;
- `Setup` — установка и обновления;
- `ForwardedEvents` — события, собранные с других узлов.

Компоненты создают Operational и другие каналы в `Applications and Services Logs`.

Запись содержит время, Provider, Event ID, Level, Computer, Record ID и EventData. Event ID не глобален: его трактуют вместе с Provider, каналом и версией шаблона.

```powershell
Get-WinEvent -ListLog * | Where-Object RecordCount -gt 0
Get-WinEvent -LogName System -MaxEvents 20
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-1)}
```

## Политика аудита

Security log содержит только события включённых категорий и подкатегорий аудита. Отсутствие события может означать отсутствие действия, выключенный аудит, потерю журнала или другой источник телеметрии.

```powershell
auditpol.exe /get /category:*
```

Типовые события для начального анализа:

- `4624` — успешный вход;
- `4625` — неуспешный вход;
- `4634`/`4647` — завершение сеанса;
- `4648` — использование явно указанных credentials;
- `4672` — специальные privileges в новом входе;
- `4688` — создание процесса при включённом аудите;
- `4697` — установка службы при соответствующей политике;
- `4720` — создание пользователя.

Номер не заменяет поля: для входа важны Logon Type, Account, Source Network Address, Workstation и Logon ID.

## Командная строка процесса

Событие создания процесса может не содержать command line, если отдельная политика не включена. Аргументы записываются открытым текстом и способны содержать секреты, поэтому доступ к журналу и политика хранения критичны.

## PowerShell logging

Полезные каналы и механизмы:

- `Microsoft-Windows-PowerShell/Operational`;
- Script Block Logging;
- Module Logging;
- Transcription;
- AMSI для интеграции проверки содержимого.

Script Block Logging даёт больше видимости, но создаёт объём и может записать чувствительные данные. Политику проектируют централизованно.

## Sysmon

Sysmon расширяет телеметрию и записывает её в стандартный Event Log. Ценность зависит от конфигурации: без фильтров возникает шум, а слишком узкие правила создают слепые зоны.

Ключевые категории:

- Process Create — путь, command line, parent, hashes, ProcessGuid;
- Network Connect;
- DNS Query;
- File Create;
- Registry events;
- Driver/Image Load;
- Process Access;
- WMI activity в соответствующих событиях.

ProcessGuid удобнее PID для корреляции во времени. Анализируют цепочку: процесс создан → разрешил имя → подключился → записал файл → изменил реестр.

## Временная шкала

1. Зафиксировать период и часовой пояс.
2. Найти исходное событие и идентификаторы корреляции.
3. Добавить процессы, входы, сеть, DNS, файлы и реестр.
4. Проверить события до и после подозрительного действия.
5. Сопоставить данные с другими узлами и сетевыми источниками.
6. Отделить наблюдаемый факт от гипотезы.

## Сохранение

```powershell
wevtutil.exe epl System .\System.evtx
Get-WinEvent -LogName System | Export-Csv .\system-events.csv -NoTypeInformation
```

EVTX лучше сохраняет структуру и метаданные, чем копирование текста. Экспорт содержит имена, адреса и команды; его защищают как чувствительные данные.

## Вопросы для собеседования

1. Почему Event ID без Provider недостаточен?
2. Почему отсутствие `4688` не доказывает отсутствие процесса?
3. Чем Sysmon дополняет стандартный аудит?
4. Зачем ProcessGuid, если есть PID?
5. Какие риски создаёт command-line logging?

## Рабочий сценарий

На внешней платформе дан Sysmon Process Create. Постройте план поиска родителя, DNS, сети, файлов и persistence, не утверждая компрометацию по одному событию.

## Официальная документация

- [Sysmon events](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/sysmon-events)
- [Command line process auditing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
