# SafeStack-Installer

**SafeStack-Installer** to skrypt bash automatyzujący instalację i konfigurację kluczowych usług związanych z bezpieczeństwem i monitorowaniem systemów Debian/Ubuntu. Umożliwia szybkie wdrożenie Pi-hole, Unbound, CrowdSec, Prometheus i Grafana, integrując je w spójny ekosystem ochrony i wizualizacji danych.

## Opis projektu

**SafeStack-Installer** został zaprojektowany, aby uprościć proces konfiguracji zaawansowanych narzędzi bezpieczeństwa i monitoringu na serwerach opartych na Debianie lub Ubuntu. Skrypt automatyzuje instalację i integrację następujących usług:

- **Pi-hole** – blokada reklam i śledzenia na poziomie sieciowym,
- **Unbound** – lokalny resolver DNS zwiększający prywatność,
- **CrowdSec** – lokalna ochrona przed atakami sieciowymi (bez rejestracji w centralnym API),
- **Prometheus** – system monitorowania zbierający metryki,
- **Grafana** – narzędzie do wizualizacji zebranych danych.

Skrypt instaluje te aplikacje, automatycznie konfiguruje ich współdziałanie oraz dostosowuje reguły zapory UFW (dla protokołów TCP i UDP), co znacząco podnosi poziom bezpieczeństwa systemu.

## Funkcjonalności

- **Interaktywna instalacja**: Użytkownik ma możliwość wyboru usług do zainstalowania oraz konfiguracji portów i hasła dla Pi-hole, co zapewnia elastyczność w różnych scenariuszach użytkowania.
- **Automatyczna konfiguracja**: Skrypt wykonuje następujące działania:
  - Sprawdza dostępność wymaganych portów.
  - Instaluje i aktualizuje wszystkie niezbędne pakiety.
  - Konfiguruje zaporę UFW dla protokołów TCP i UDP.
  - Integruje usługi, np. ustawia Pi-hole do korzystania z Unbound jako resolvera DNS, zwiększając prywatność.
- **Obsługa błędów**: W przypadku problemów skrypt loguje zdarzenia do pliku `/var/log/install_script.log` i oferuje opcje: pominięcie problematycznego kroku lub przerwanie instalacji, co podnosi niezawodność procesu.

## Wymagania

- **System operacyjny**: Debian (zalecane 11+) lub Ubuntu (zalecane 20.04+).
- **Uprawnienia**: Skrypt wymaga uruchomienia z uprawnieniami roota (np. za pomocą `sudo`).
- **Dostęp do Internetu**: Niezbędny do pobierania pakietów i aktualizacji systemu.
- **Wolne porty**: Skrypt zweryfikuje dostępność portów i ostrzeże w przypadku konfliktów.

## Instalacja i uruchomienie

1. **Klonowanie repozytorium**:
   ```bash
   git clone https://github.com/<nazwa_uzytkownika>/SafeStack-Installer.git
   cd SafeStack-Installer
   ```

2. **Uruchomienie skryptu**:
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```

3. **Postępuj zgodnie z instrukcjami**: Skrypt przeprowadzi Cię przez proces instalacji, pytając o wybór usług i ich konfigurację.

4. **Weryfikacja instalacji**: Po zakończeniu możesz sprawdzić działanie usług, np.:
   - Pi-hole: `sudo systemctl status pihole-FTL`
   - Unbound: `sudo systemctl status unbound`
   - CrowdSec: `sudo cscli metrics`
   - Prometheus: `sudo systemctl status prometheus`
   - Grafana: `sudo systemctl status grafana-server`

## Konfiguracja i integracja

Po instalacji usługi są wstępnie skonfigurowane do współpracy. Poniżej znajdziesz linki do paneli administracyjnych oraz wskazówki dotyczące dostosowania:

- **Pi-hole**: Panel administracyjny: `http://<IP_SERWERA>/admin/`. Możesz dostosować listy blokad lub dodać własne reguły.
- **Grafana**: Działa na porcie 3000: `http://<IP_SERWERA>:3000`. Domyślne dane logowania: admin/admin. Dodaj Prometheus jako źródło danych.
- **Prometheus**: Metryki dostępne pod: `http://<IP_SERWERA>:9090`. Edytuj `/etc/prometheus/prometheus.yml` dla dodatkowych usług.
- **CrowdSec**: Sprawdź stan: `sudo cscli metrics`. Dodawaj własne scenariusze ochrony.
- **Unbound**: Logi w `/var/log/unbound.log`. Konfiguracja w `/etc/unbound/unbound.conf`.

## Logi i debugowanie

Wszystkie zdarzenia zapisywane są w pliku:
```bash
cat /var/log/install_script.log
```

W razie problemów użyj poniższych komend do debugowania:
- Pi-hole: `pihole -d`
- Unbound: `unbound -d`
- CrowdSec: `sudo cscli explain`

Zgłoś problemy w sekcji Issues na GitHubie.

## Autorzy

- **Acid** – [GitHub](https://github.com/<nazwa_uzytkownika>)

