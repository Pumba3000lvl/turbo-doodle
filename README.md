Проект: SSH + HTTP Honeypot (MVP)

Цель
Собирать и анализировать попытки атак на SSH и простые HTTP эндпоинты локально.

Запуск (локально)
1. python -m venv .venv
2. source .venv/bin/activate
3. pip install -r requirements.txt
4. python run_ssh.py  # запуск SSH honeypot

Структура
- run_ssh.py            — запуск SSH honeypot
- src/honeypot/ssh_honeypot.py — реализация простого SSH-honeypot на paramiko
- src/honeypot/http_honeypot.py — простой HTTP honeypot (Flask)
- src/honeypot/metrics_exporter.py — Prometheus exporter (/metrics)
- grafana/dashboard.json  — пример Grafana dashboard (для SQLite)
- honeypot.db           — SQLite БД с логами (создаётся при запуске)
- logs/                 — папка для дополнительных логов

Примечание
Honeypot имитирует shell и логирует имена пользователей, пароли и введённые команды — не выполняет команды на хосте.

Grafana и Prometheus

1) Быстрая опция: Grafana + SQLite plugin (локально)
- Установите плагин "frser-sqlite-datasource" или официальный sqlite плагин в Grafana (https://grafana.com/grafana/plugins)
- Добавьте datasource: Configuration → Data sources → Add data source → SQLite. В поле Database path укажите полный путь к honeypot.db на машине, где запущен Grafana сервер.
- Откройте Grafana → Dashboards → Import → Upload JSON и выберите grafana/dashboard.json из проекта.
- Перед импортом в JSON замените "__REPLACE_WITH_DATASOURCE_UID__" на UID вашего SQLite datasource или привяжите datasource в UI при импорте.

2) Рекомендуемая опция: Prometheus exporter (для Grafana через Prometheus)
- Установите зависимости и запустите exporter:
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python src/honeypot/metrics_exporter.py
  Экспорт метрик будет доступен на http://localhost:8000/metrics

- Пример scrape-конфигурации Prometheus (prometheus.yml):
  scrape_configs:
    - job_name: 'honeypot'
      static_configs:
        - targets: ['localhost:8000']

- Перезапустите Prometheus с этой конфигурацией и добавьте Prometheus datasource в Grafana (URL: http://<prometheus-host>:9090).
- Создайте новые панели в Grafana с PromQL, например:
  - Events over time: sum by (event_type) (increase(honeypot_events_total[5m]))
  - Top IPs: topk(20, sum by (src_ip) (increase(honeypot_events_by_ip[1h]))) — может понадобиться адаптация экспортером, т.к. метки динамические
  - Suspicious passwords: honeypot_suspicious_passwords_total

Примечание: grafana/dashboard.json в этом репозитории рассчитан на SQLite datasource. При использовании Prometheus добавьте соответствующие PromQL-панели или адаптируйте JSON.

Если нужно, помогу:
- подготовить Prometheus-ready Grafana JSON (панели с PromQL),
- показать, как настроить Grafana на удалённый файл honeypot.db через sqlite-плагин,
- или запустить экспортер как systemd-сервис.

Безопасность и тесты

- Быстрая проверка безопасности: scripts/security_check.py — запускает базовые статические и конфигурационные проверки.
- Тест для CI: tests/test_security.py запускает скрипт проверки; добавьте в CI pipeline команду:
    python -m pip install -r requirements.txt
    python -m pip install pytest
    pytest -q tests/test_security.py

Рекомендую запускать security_check и тесты в CI до деплоя.
