# letsencrypt-certificate

Утилита для автоматического получения и деплоя Let's Encrypt SSL-сертификатов через DNS-01 challenge (NIC.RU).

## Что делает

1. Получает сертификаты от Let's Encrypt по протоколу ACME (DNS-01)
2. Создаёт TXT-записи в NIC.RU DNS для подтверждения домена
3. Деплоит сертификаты на серверы — локально или по SSH
4. Проверяет SSL на всех портах и отправляет отчёт в Telegram / Max.ru

## Конфигурация

```bash
cp config.ini.example config.ini
# заполнить config.ini
```

Ключевые секции `config.ini`:

| Секция | Что настраивает |
|---|---|
| `[log]` | Путь к лог-файлу (`folder`), папка сертификатов (`certificate_folder`) |
| `[log.http]` | Отправка логов по HTTP на удалённый сервер (опционально) |
| `[notifier.telegram]` | Уведомления через Telegram — токен бота и `recipient` |
| `[notifier.maxru]` | Уведомления через Max.ru — `access_token` и `chat_id` |
| `[acme]` | URL Let's Encrypt (`directory_url`), email |
| `[nic]` | Учётные данные NIC.RU API, `token_file` для кэша токена |
| `[dns]` | Интервал и лимит проверки TXT-записи, DNS-резолвер |
| `[certificate "name"]` | Домены, порты, тип деплоя (`local`/`ssh`), `renew_before_days` |

Можно подключить одновременно несколько нотификаторов — каждый из блоков `[notifier.*]` будет использован независимо.

Для тестов используйте staging в `[acme]`:
```ini
directory_url = https://acme-staging-v02.api.letsencrypt.org/directory
```

### HTTP-лог (опционально)

Блок `[log.http]` позволяет дублировать каждую строку лога на удалённый HTTP-сервер POST-запросом:

```ini
[log.http]
enable      = true
host        = 192.168.1.100
port        = 8080
read_port   = 8080   ; порт для ссылки в уведомлении
path        = letsencrypt-certificate
timeout_sec = 10
```

URL записи: `http://host:port/path/<logFileName>`, тело: `t=<строка>&no_date=true`.
Если `read_port` не задан, ссылка на лог в уведомлении не выводится.

## Логика обновления

Программа запускается ежедневно (по cron) и проверяет срок действия каждого сертификата.
Обновление выполняется только если до истечения осталось не более `renew_before_days` дней (по умолчанию 30).
Если все сертификаты актуальны — уведомление отправляется без обращения к NIC.RU и Let's Encrypt.

## Флаги

| Флаг | Описание |
|---|---|
| `--config path` | Путь к файлу конфигурации (по умолчанию `config.ini`) |
| `--debug` | Включить подробное логирование |
| `--list` | Показать имена всех сертификатов и выйти |
| `--certs name1,name2` | Обработать только указанные сертификаты |
| `--force` | Принудительно обновить, игнорируя срок истечения |

Комбинации:
- Ежедневный cron — без флагов: `./letsencrypt-certificate --config config.ini`
- Ручной перевыпуск конкретного сертификата: `./letsencrypt-certificate --config config.ini --certs example.com --force`
- Принудительное обновление всех: `./letsencrypt-certificate --config config.ini --force`

## Сборка и запуск

```bash
make build   # статичная сборка бинарника (CGO_ENABLED=0)
make run     # запуск с config.ini
make vet     # проверка go vet
make clean   # удалить бинарник
```

Или напрямую:
```bash
./letsencrypt-certificate --config config.ini
```

## Зависимости

Единственная внешняя зависимость: `golang.org/x/crypto` (ACME + SSH).
Всё остальное — стандартная библиотека Go.
