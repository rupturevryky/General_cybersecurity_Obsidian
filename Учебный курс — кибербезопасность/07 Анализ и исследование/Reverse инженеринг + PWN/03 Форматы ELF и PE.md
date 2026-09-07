# Форматы ELF и PE

Формат исполняемого файла сообщает загрузчику, как разместить код и данные, какие зависимости подключить и откуда начать выполнение.

## ELF

ELF распространён в Linux и Unix-подобных системах. ELF header описывает архитектуру и таблицы. Section headers удобны линкеру и анализатору; program headers описывают сегменты, загружаемые в память. Секции и сегменты — не одно и то же.

Важные элементы: `.text`, `.rodata`, `.data`, `.bss`, таблицы символов, relocation, GOT и PLT. Динамический загрузчик разрешает внешние символы с учётом режима связывания.

## PE

Portable Executable используется Windows. Он включает DOS stub, PE headers, optional header, таблицу секций и data directories. Import table показывает заявленные внешние функции, export table — предоставляемые символы. Resources могут содержать конфигурацию, изображения и вложенные данные.

## Ограничения анализа

Импорт функции не доказывает её вызов. Упаковщик может скрыть исходные секции и импорты до выполнения. Timestamp заголовка может быть изменён и не является надёжным доказательством времени сборки.

## Полезные безопасные команды

```bash
file sample
sha256sum sample
readelf -h -l -S sample
objdump -d sample
```

Команды только читают файл, но неизвестный объект всё равно нельзя открывать средствами, запускающими preview или embedded content.

## Источники

- [ELF specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Microsoft PE format](https://learn.microsoft.com/windows/win32/debug/pe-format)

