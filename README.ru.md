# Laz MASQUE Server

[![Лицензия][license-badge]][license] [![Релиз][release-badge]][releases] [![Сборка][build-badge]][build] [![Issues][issues-badge]][issues]

[English](README.md) | **Русский**

[license-badge]: https://img.shields.io/badge/license-MIT-blue
[license]: LICENSE
[release-badge]: https://img.shields.io/github/v/release/ro-gri/laz-masque-server?style=flat-square
[releases]: https://github.com/ro-gri/laz-masque-server/releases
[build-badge]: https://github.com/ro-gri/laz-masque-server/actions/workflows/ci.yml/badge.svg?branch=main
[build]: https://github.com/ro-gri/laz-masque-server/actions/workflows/ci.yml
[issues-badge]: https://img.shields.io/github/issues/ro-gri/laz-masque-server?style=flat-square
[issues]: https://github.com/ro-gri/laz-masque-server/issues

Laz MASQUE Server — форк
[zenith-ent/masque-server](https://github.com/zenith-ent/masque-server),
высокопроизводительного MASQUE-прокси на Rust. Передаёт TCP, UDP и IP-трафик
с помощью CONNECT, CONNECT-UDP и CONNECT-IP поверх HTTP/2 и HTTP/3.

Дополнения к исходному проекту:

- **Исходящая маршрутизация через SOCKS5** — отправка TCP и UDP напрямую или
  через локальный SOCKS5-прокси по правилам IP/CIDR.
  Подробнее: [маршрутизация](docs/outbound-routing.md).
- **HTTP-авторизация** — проверка Basic и клиентских сертификатов через внешний
  сервер авторизации, с постоянными соединениями и кешем.
  Подробнее: [авторизация](docs/http-authorization.md).
- **Статистика и управление сессиями** — счётчики трафика, список UUID учётных
  данных онлайн и отключение сессий через `kickAuth` в локальном API.
  Подробнее: [контракт API](docs/accounting.md).

Готовые релизы доступны для **Linux x86_64 и ARM64**. Установка и обновления
используют [релизы этого репозитория][releases]. Сообщения об ошибках и предложения
принимаются в [Issues][issues]. Оригинальная лицензия MIT и уведомления
об авторских правах сохранены.

## Версионирование

Версии релизов имеют формат `v<версия-laz>+masque.<версия-исходной-базы>`,
например `v0.1.0+masque.0.15.0`:

- `0.1.0` — версия Laz MASQUE Server.
- `masque.0.15.0` — версия исходного проекта, на которой основан релиз.

Каждый новый релиз увеличивает версию Laz, в том числе при обновлении исходной
базы. Метаданные после `+` обозначают базу и не влияют на порядок версий.
Первый релиз — `v0.1.0+masque.0.15.0`.

## Возможности

### 🌐 Стандартные протоколы

CONNECT для TCP, [CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298)
и [CONNECT-IP](https://www.rfc-editor.org/rfc/rfc9484). HTTP/3 работает через QUIC;
HTTP/2 обеспечивает транспорт TCP/TLS, когда UDP недоступен.
Для передачи CONNECT-IP нужны Linux TUN и маршрутизация на хосте.

### 🔀 Гибкая маршрутизация

Выбор DIRECT или SOCKS5 для CONNECT и CONNECT-UDP по IP/CIDR назначения.
Обновление DIRECT CIDR-файла без перезапуска сервера. Глобальные политики
и ограничения слушателей управляют доступом к назначениям.
[Настройка маршрутизации](docs/outbound-routing.md).

### 🔐 Авторизация

Basic или клиентские сертификаты, единый источник авторизации `file` или `http`.
У каждой записи учётных данных постоянный UUID. Несколько слушателей могут
обслуживать разные транспорты и режимы авторизации в одном процессе.
[Конфигурация](docs/configuration.md#authentication).

### 📊 Трафик и сессии

Локальный API предоставляет накопленные счётчики трафика, UUID онлайн
и управление сессиями. Для мониторинга доступны необязательные метрики
Prometheus, проверки состояния и структурированные логи.
[API статистики](docs/accounting.md) · [Мониторинг](docs/observability.md).

### ⚡ Производительность

Обработка QUIC на нескольких ядрах, ограниченные очереди, обратное давление
и оптимизации UDP на Linux.
[Архитектура](docs/architecture.md) · [Производительность](docs/performance.md).

### 🚀 Установка Linux одной командой

Установка последнего стабильного релиза на Linux x86_64 и ARM64:

```sh
curl -fsSL https://raw.githubusercontent.com/ro-gri/laz-masque-server/main/install-latest.sh | sudo sh
```

Та же команда обновляет существующую установку, сохраняя конфигурацию.
[Инструкция по установке и настройке](docs/deployment.md#one-command-install).

## Документация

Подробная документация доступна на английском языке.

- [Конфигурация](docs/configuration.md) — слушатели, учётные данные и политики.
- [Развёртывание](docs/deployment.md) — установка, TLS, systemd и обновления.
- [Маршрутизация SOCKS5](docs/outbound-routing.md) — выбор маршрута и обновление CIDR.
- [HTTP-авторизация](docs/http-authorization.md) — внешний сервер авторизации и кеш.
- [API статистики](docs/accounting.md) — трафик, UUID онлайн и `kickAuth`.
- [Диагностика](docs/troubleshooting.md) — `laz-masque-probe`, проверки и support bundle.
- [Управление серверами](docs/operations.md) — необязательные инструменты `laz-masque-ops` и AI Skill.
- [Протоколы](docs/protocols.md) · [Безопасность](docs/security.md) · [История изменений](CHANGELOG.md).

## Разработка

Сборка из исходников:

```sh
cargo build --release --bin laz-masque-server
```

Linux — целевая платформа для рабочих установок. Переносимые пути HTTP/2
и HTTP/3 также тестируются на macOS. Инструкции для разработки и проверок:
[CONTRIBUTING.md](CONTRIBUTING.md), [архитектура](docs/architecture.md)
и [тестирование](docs/testing.md).

## Лицензия

[MIT](LICENSE).
