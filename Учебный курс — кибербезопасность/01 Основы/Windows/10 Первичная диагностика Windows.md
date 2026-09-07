# Первичная диагностика Windows

> [!abstract] Результат
> Ученик выполняет воспроизводимый triage: фиксирует контекст, собирает volatile и устойчивые данные, отделяет факт от гипотезы и не ухудшает состояние системы.

## Цель triage

Первичная диагностика не обязана сразу доказать первопричину. Её задача — определить масштаб, срочность, затронутые функции, необходимые данные и безопасное следующее действие.

## Правила до команд

- подтвердить разрешение и область работ;
- записать время, часовой пояс, имя узла и пользователя;
- описать симптом словами наблюдателя;
- не перезагружать и не «чистить» систему без оценки потери данных;
- не запускать неизвестные инструменты на потенциально скомпрометированном узле;
- сохранять исходные результаты и hash экспортированных файлов;
- учитывать влияние сбора на производительность и доказательства.

## Шаг 1. Контекст системы

```powershell
Get-Date
hostname.exe
whoami /all
Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture
Get-CimInstance Win32_ComputerSystem | Select-Object Domain,PartOfDomain,Manufacturer,Model
```

Фиксируют физическая это система или VM, критичность, владелец и известные изменения.

## Шаг 2. Ресурсы

```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 15
Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime
Get-Volume | Select-Object DriveLetter,FileSystemLabel,Size,SizeRemaining,HealthStatus
```

Высокий CPU — симптом. Нужно связать процесс со временем, пользователем и задачей. Заполненный диск проверяют по тому, какой путь растёт, а не удаляют случайные журналы.

## Шаг 3. Процессы, службы и запуск

```powershell
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
Get-CimInstance Win32_Service | Where-Object State -ne 'Running'
Get-ScheduledTask | Where-Object State -ne 'Disabled'
```

Сравнивают с baseline и назначением узла. Не вся редкая программа подозрительна, и не вся штатно названная безопасна.

## Шаг 4. Сеть

```powershell
Get-NetIPConfiguration
Get-NetRoute
Get-DnsClientCache
Get-NetTCPConnection
Get-NetUDPEndpoint
```

Для соединения фиксируют local/remote address, port, state, owning process и время. Внешний адрес оценивают вместе с доменом, процессом и назначением.

## Шаг 5. Журналы

```powershell
$start = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start}
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$start}
```

Добавляют Security, PowerShell, Defender и Sysmon только если они доступны и релевантны. Узкое окно времени расширяют постепенно.

## Шаг 6. Изменения и защита

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15
Get-MpComputerStatus
Get-MpThreatDetection
Get-NetFirewallProfile
```

Проверяют установку ПО, обновления, policy changes, новые учётные записи, службы и задачи.

## Приоритеты реакции

- Риск для людей или критического процесса — немедленная эскалация.
- Активная компрометация — координация containment с SOC/IR, а не самостоятельное удаление.
- Операционный сбой — сохранить данные, применить минимально изменяющее исправление и проверить результат.
- Недостаток данных — явно записать, чего нет и как это влияет на уверенность.

## Формат вывода

```text
Факт: служба X завершилась в 10:14 с кодом Y.
Источник: System, Provider ..., Record ID ...
Гипотеза: ошибка конфигурации после изменения Z.
Альтернативы: зависимость, нехватка ресурса, блокировка защиты.
Следующая проверка: журнал приложения и diff конфигурации.
Риск действия: restart создаст краткий простой и изменит volatile state.
```

## Вопросы для собеседования

1. Что собирают до перезагрузки?
2. Почему высокий CPU не является первопричиной?
3. Как связать сетевое соединение с процессом?
4. Когда triage должен перейти в incident response?
5. Чем факт отличается от гипотезы?

## Итоговое задание

На внешней платформе исследуйте кейс «пользователь сообщает о медленной работе и всплывающем окне». Составьте временную шкалу, таблицу фактов, три гипотезы и план проверок. Не выполняйте изменяющих действий, пока не описан риск потери данных.
