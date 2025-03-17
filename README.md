SafeStack-Installer

Automatyczny instalator usług bezpieczeństwa i monitoringu dla systemów Debian/Ubuntu

Opis projektu

SafeStack-Installer to skrypt bash, który automatyzuje instalację oraz konfigurację kluczowych usług związanych z bezpieczeństwem i monitorowaniem systemu. Dzięki niemu możesz szybko uruchomić:

Pi-hole – blokadę reklam i śledzenia,

Unbound – lokalny resolver DNS zwiększający prywatność,

CrowdSec – ochronę przed atakami sieciowymi, działającą lokalnie bez rejestracji w centralnym API,

Prometheus – system monitorowania zbierający metryki,

Grafana – narzędzie do wizualizacji zebranych danych.

Skrypt nie tylko instaluje wyżej wymienione aplikacje, ale także automatycznie konfiguruje integrację między nimi oraz ustawia odpowiednie reguły zapory UFW, co znacząco zwiększa bezpieczeństwo systemu.

Funkcjonalności

Interaktywna instalacja:Użytkownik wybiera, które usługi mają zostać zainstalowane oraz konfiguruje porty i hasło dla Pi-hole.

Automatyczna konfiguracja:Skrypt:

Sprawdza dostępność portów.

Instaluje wymagane pakiety.

Konfiguruje zaporę UFW (zarówno dla TCP, jak i UDP).

Integruje usługi (np. konfiguruje Pi-hole do korzystania z Unbound).

Obsługa błędów:W przypadku wystąpienia problemu, skrypt loguje zdarzenia do /var/log/install_script.log oraz umożliwia interaktywne podjęcie decyzji – pominięcie danego kroku lub przerwanie całego procesu.

Wymagania

System: Debian lub Ubuntu.

Uprawnienia: Skrypt musi być uruchomiony jako root (np. za pomocą sudo).

Dostęp do Internetu: Niezbędny do pobierania pakietów i aktualizacji systemu.

Instalacja i uruchomienie

Klonowanie repozytorium:

git clone <URL_repozytorium>
cd SafeStack-Installer

Uruchomienie skryptu:

chmod +x install.sh
sudo ./install.sh

Postępuj zgodnie z instrukcjami wyświetlanymi na ekranie.

Konfiguracja i integracja

Po instalacji można ręcznie sprawdzić i dostosować konfigurację poszczególnych usług:

Pi-hole: Panel administracyjny dostępny pod http://<IP_SERWERA>/admin/

Grafana: Domyślnie działa na porcie 3000 http://<IP_SERWERA>:3000

Prometheus: Dane dostępne pod http://<IP_SERWERA>:9090

CrowdSec: Możliwość sprawdzenia stanu usługi przez sudo cscli metrics

Unbound: Logi działania w /var/log/unbound.log

Logi i debugowanie

Wszystkie istotne zdarzenia zapisywane są w pliku logów:

cat /var/log/install_script.log

Jeśli napotkasz problemy, sprawdź ten plik lub skontaktuj się z nami na GitHubie.

Autorzy
Acid
