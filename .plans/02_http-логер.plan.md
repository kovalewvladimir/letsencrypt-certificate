# План: HTTP логер в Go (аналог Python SimpleHttpHandler)

## Статус: ГОТОВО

## Цель
Реализовать асинхронный HTTP-логер как `slog.Handler`, который на каждую запись делает POST на удалённый сервер (form-encoded `t=...&no_date=true`), с конфигурацией через `[log.http]` в config.ini.

## Шаги

- [x] Шаг 1: `internal/config/config.go` — добавить структуру `HTTPLogConfig` (поля: Enable bool, Host, Port, Path string, TimeoutSec int)
- [x] Шаг 2: `internal/config/config.go` — добавить поле `HTTPLog HTTPLogConfig` в структуру `Config`
- [x] Шаг 3: `internal/config/config.go` — добавить парсинг секции `[log.http]` в функции `Load()` (с default TimeoutSec=10)
- [x] Шаг 4: `cmd/logger.go` — добавить структуру `httpHandler` (поля: queue chan string, client *http.Client, url string, level slog.Level, certName string, debug bool)
- [x] Шаг 5: `cmd/logger.go` — реализовать методы `Enabled`, `Handle` (форматирование + запись в канал), `WithAttrs` (захват "cert" атрибута), `WithGroup` (возвращает self)
- [x] Шаг 6: `cmd/logger.go` — добавить `newHTTPHandler` конструктор: инициализирует `http.Client` с таймаутом, канал с буфером 256, запускает фоновую горутину-воркер (читает из канала, делает POST, ошибки — молча или в debug)
- [x] Шаг 7: `cmd/logger.go` — обновить сигнатуру `buildLogger`: добавить параметры `logFileName string` и `httpCfg config.HTTPLogConfig`; добавить `httpHandler` в `multiHandler` если `httpCfg.Enable == true`
- [x] Шаг 8: `cmd/main.go` — вынести генерацию `logFileName` (`time.Now().Format(...)`) до первого вызова `buildLogger`; передавать `logFileName` и `cfg.HTTPLog` в оба вызова `buildLogger`
- [x] Шаг 9: `config.ini.example` — добавить раздел `[log.http]` с примером (закомментирован)

## Критерий готовности
- `go build ./...` проходит без ошибок
- При `enable = true` в `[log.http]` в `buildLogger` добавляется httpHandler, который отправляет POST на каждую лог-запись
- При недоступном HTTP-сервере программа продолжает работу (ошибки игнорируются / пишутся в debug)
- Формат тела запроса: `t=2006-01-02 15:04:05\tcertName:\tINFO:\tmessage key=val&no_date=true`
- URL: `http://host:port/path/logFileName` — тот же `logFileName`, что у файлового лога

## Зависимости
Нет внешних зависимостей — используется только стандартная библиотека (`net/http`, `net/url`, `log/slog`).

## Заметки
<!-- прогресс и комментарии — заполняется при выполнении -->

### Детали реализации
- `queue chan string` — буфер 256 строк; если переполнен — запись дропается молча
- `WithAttrs`: сканирует attrs в поиске ключа `"cert"`, создаёт shallow copy с обновлённым `certName`
- Горутина-воркер живёт до конца программы (канал никогда не закрывается — это нормально для данного use-case)
- Если `logDir == ""` и HTTP сконфигурирован — `logFileName` генерируется в любом случае
