# letsencrypt-certificate

Утилита для автоматического получения и деплоя Let's Encrypt SSL-сертификатов через DNS-01 challenge (NIC.RU).

## Что делает

1. Получает сертификаты от Let's Encrypt по протоколу ACME (DNS-01)
2. Создаёт TXT-записи в NIC.RU DNS для подтверждения домена
3. Деплоит сертификаты на серверы — локально или по SSH
4. Проверяет SSL на всех портах и отправляет отчёт в Telegram

## Установка

```bash
git clone https://github.com/kovalewvladimir/letsencrypt-certificate
cd letsencrypt-certificate
make build
```

## Конфигурация

```bash
cp config.ini.example config.ini
# заполнить config.ini
```

Ключевые секции `config.ini`:

| Секция | Что настраивает |
|---|---|
| `[log]` | Путь к лог-файлу, папка сертификатов |
| `[notifier.telegram]` | Токен бота и chat_id |
| `[acme]` | URL Let's Encrypt, email |
| `[nic]` | Учётные данные NIC.RU API |
| `[dns]` | Интервал и лимит проверки TXT-записи |
| `[certificate "name"]` | Домены, порты, тип деплоя (local/ssh) |

Для тестов используйте staging в `[acme]`:
```ini
directory_url = https://acme-staging-v02.api.letsencrypt.org/directory
```

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
make build   # статичная сборка бинарника
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
