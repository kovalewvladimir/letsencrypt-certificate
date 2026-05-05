BINARY := letsencrypt-certificate
CMD    := ./cmd/...

.PHONY: build run vet clean help

help:
	@echo "Доступные команды:"
	@echo "  make build   — статичная сборка бинарника (CGO_ENABLED=0)"
	@echo "  make run     — запуск с config.ini"
	@echo "  make vet     — проверка go vet"
	@echo "  make clean   — удалить бинарник"

build:
	CGO_ENABLED=0 go build -o $(BINARY) $(CMD)

run:
	./$(BINARY) --config config.ini

vet:
	go vet $(CMD)

clean:
	rm -f $(BINARY)
