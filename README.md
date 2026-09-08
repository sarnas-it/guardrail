# Guardrail

Container action для GitHub: сканирует дифф PR/push на утечки секретов и персональных данных (ПДн РФ) прямо в раннере — код репозитория наружу не отправляется.

## Быстрый старт

```yaml
steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0
  - uses: docker://ghcr.io/sarnas-it/guardrail:v0.1.0
    with:
      base: ${{ github.event.pull_request.base.sha || github.event.before }}
      head: ${{ github.sha }}
```

Пайплайн упадёт (exit 1), если в новых изменениях найден секрет. ПДн РФ печатаются как предупреждения (exit 0).

## Локально

```bash
go build -o guardrail ./cmd/guardrail
./guardrail scan --repo . --base HEAD~1 --head HEAD
```

## Конфиг guardrail.yml

См. `examples/guardrail.yml`. Значения находок маскируются; полные значения — `GUARDRAIL_REVEAL=1` или `output.reveal: true`.

## Правила

Секреты блокируют: AWS/GCP/слак/GitHub/telegram-ключи, PEM, JWT, строки БД, generic high-entropy. ПДн РФ (телефон, email, ИНН, СНИЛС, паспорт) — предупреждения.
