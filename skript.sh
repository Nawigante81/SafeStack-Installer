#!/bin/bash
set -e  # Zakończ skrypt natychmiast po wystąpieniu błędu

# -----------------------------------------------------------------------------
# Funkcje pomocnicze
# -----------------------------------------------------------------------------

function log_message {
  timestamp=$(date +"%Y-%m-%d %H:%M:%S UTC")
  echo "$timestamp - $1" | tee -a /var/log/install_script.log
}

function get_error_action {
  local prompt="$1"
  while true; do
    read -p "$prompt Wybierz opcję: [s]kip/[e]xit: " action
    case "$action" in
      [Ee]*) return 0 ;;  # exit
      [Ss]*) return 1 ;;  # skip
      *) log_message "Niepoprawna opcja. Wybierz 's' lub 'e'." ;;
    esac
  done
}

# Funkcja ujednolica wykonywanie poleceń z obsługą błędów
function exec_cmd {
  local desc="$1"
  shift
  if ! "$@"; then
    log_message "Błąd: $desc"
    if [ $(get_error_action "Co zrobić po błędzie: $desc?") -eq 0 ]; then
      log_message "Skrypt przerwany na życzenie użytkownika."
      exit 1
    else
      log_message "Pominięto: $desc"
      return 1
    fi
  fi
}

if [ "$EUID" -ne 0 ]; then
  log_message "Błąd: Skrypt musi być uruchomiony jako root. Uruchom skrypt za pomocą 'sudo bash <nazwa_skryptu>'"
  exit 1
fi

function check_port_availability {
  local port=$1
  local service=$2
  if ss -tuln | grep -q ":$port"; then
    log_message "Błąd: Port $port jest już używany przez inną usługę. $service nie może zostać uruchomiony."
    return 1
  else
    log_message "Port $port jest dostępny."
    return 0
  fi
}

function install_package {
  local package=$1
  if dpkg -s "$package" &> /dev/null; then
    log_message "Pakiet $package jest już zainstalowany (pomijanie instalacji)."
    return 0
  else
    log_message "Aktualizacja repozytoriów..."
    exec_cmd "aktualizacja repozytoriów dla $package" apt update
    log_message "Instalacja pakietu $package..."
    exec_cmd "instalacja pakietu $package" apt install -y "$package"
    log_message "Pakiet $package zainstalowany pomyślnie."
    return 0
  fi
}

function configure_ufw {
  local port=$1
  local description="$2 (skrypt)"
  for proto in tcp udp; do
    log_message "Konfiguracja UFW: zezwolenie na port $port dla $description ($proto)..."
    if ! ufw allow "$port/$proto" comment "$description"; then
      log_message "Błąd: Nie udało się dodać reguły UFW dla portu $port ($proto)."
      if [ $(get_error_action "Co zrobić po błędzie dodawania reguły UFW dla portu $port ($proto)?") -eq 0 ]; then
        log_message "Skrypt przerwany na życzenie użytkownika."
        exit 1
      else
        log_message "Pominięto dodawanie reguły UFW dla portu $port ($proto)."
      fi
    else
      log_message "Reguła UFW dla portu $port ($proto) dodana."
    fi
  done
}

function check_service_status {
  local service=$1
  log_message "Sprawdzanie statusu usługi $service..."
  systemctl status "$service" --no-pager
  if systemctl is-active --quiet "$service"; then
    log_message "Usługa $service działa poprawnie."
    return 0
  else
    log_message "Błąd: Usługa $service nie działa. Sprawdź logi (journalctl -u $service)."
    if [ $(get_error_action "Co zrobić po błędzie statusu usługi $service?") -eq 0 ]; then
      log_message "Skrypt przerwany na życzenie użytkownika."
      exit 1
    else
      log_message "Pominięto sprawdzenie statusu usługi $service."
      return 1
    fi
  fi
}

function test_connection {
  local type=$1
  local target=$2
  local service=$3
  log_message "Testowanie połączenia z $service ($target) używając $type..."
  case "$type" in
    dig)
      local ip_port=(${target//@/ })
      local ip=${ip_port[0]}
      local port=${ip_port[1]}
      if ! dig google.com @$ip -p $port +short | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        log_message "Błąd: Nie udało się połączyć z $service ($ip@$port)."
        if [ $(get_error_action "Co zrobić po błędzie połączenia z $service ($ip@$port)?") -eq 0 ]; then
          log_message "Skrypt przerwany na życzenie użytkownika."
          exit 1
        else
          log_message "Pominięto test połączenia z $service ($ip@$port)."
          return 1
        fi
      else
        log_message "Połączenie z $service ($ip@$port) działa poprawnie."
        return 0
      fi
      ;;
    curl)
      local status_code
      status_code=$(curl -s -o /dev/null -w "%{http_code}" "$target" || echo "000")
      if [ "$status_code" -eq 200 ]; then
        log_message "Połączenie z $service ($target) działa poprawnie (HTTP 200)."
        return 0
      elif [ "$status_code" -eq "000" ]; then
        log_message "Błąd: curl nie mógł nawiązać połączenia z $service ($target)."
        if [ $(get_error_action "Co zrobić po błędzie połączenia curl z $service ($target)?") -eq 0 ]; then
          log_message "Skrypt przerwany na życzenie użytkownika."
          exit 1
        else
          log_message "Pominięto test połączenia z $service ($target)."
          return 1
        fi
      else
        log_message "Błąd: Nie udało się połączyć z $service ($target). Kod HTTP: $status_code."
        if [ $(get_error_action "Co zrobić po błędzie połączenia z $service ($target)?") -eq 0 ];then
          log_message "Skrypt przerwany na życzenie użytkownika."
          exit 1
        else
          log_message "Pominięto test połączenia z $service ($target)."
          return 1
        fi
      fi
      ;;
    *)
      log_message "Błąd: Nieznany typ testu połączenia: $type."
      if [ $(get_error_action "Co zrobić po nieznanym typie testu połączenia: $type?") -eq 0 ];then
        log_message "Skrypt przerwany na życzenie użytkownika."
        exit 1
      else
        log_message "Pominięto test połączenia (nieznany typ)."
        return 1
      fi
      ;;
  esac
}

function enable_and_start_service {
  local service=$1
  log_message "Włączanie i uruchamianie usługi $service..."
  if ! systemctl is-enabled "$service"; then
    exec_cmd "włączanie usługi $service" systemctl enable "$service"
  else
    log_message "Usługa $service jest już włączona (pomijanie włączania)."
  fi

  if ! systemctl is-active --quiet "$service"; then
    exec_cmd "uruchamianie usługi $service" systemctl start "$service"
  else
    log_message "Usługa $service jest już uruchomiona (pomijanie uruchamiania)."
  fi
  check_service_status "$service"
}

function test_network {
  log_message "Testowanie łączności sieciowej..."
  if ping -c 4 8.8.8.8 > /dev/null 2>&1; then
    log_message "Łączność sieciowa działa."
    return 0
  else
    log_message "Błąd: Brak łączności sieciowej."
    if [ $(get_error_action "Co zrobić po błędzie łączności sieciowej?") -eq 0 ]; then
      log_message "Skrypt przerwany na życzenie użytkownika."
      exit 1
    else
      log_message "Pominięto test łączności sieciowej."
      return 1
    fi
  fi
}

function create_config_file_if_not_exists {
  local config_file="$1"
  local content="$2"
  local message="$3"
  if [ -f "$config_file" ]; then
    log_message "Plik konfiguracyjny $config_file dla $message już istnieje (pomijanie tworzenia)."
  else
    log_message "Tworzenie pliku konfiguracyjnego $config_file dla $message..."
    echo "$content" > "$config_file"
    if [ -f "$config_file" ]; then
      log_message "Plik $config_file utworzony pomyślnie."
    else
      log_message "Błąd: Nie udało się utworzyć pliku $config_file."
      if [ $(get_error_action "Co zrobić po błędzie tworzenia pliku $config_file dla $message?") -eq 0 ]; then
        log_message "Skrypt przerwany na życzenie użytkownika."
        exit 1
      else
        log_message "Pominięto tworzenie pliku $config_file."
      fi
    fi
  fi
}

# -----------------------------------------------------------------------------
# Konfiguracja instalowanych usług
# -----------------------------------------------------------------------------

PIHOLE_WEB_PASSWORD=""
UNBOUND_IP="127.0.0.1"
UNBOUND_PORT="5335"
PROMETHEUS_VERSION="2.48.0"
PROMETHEUS_PORT="9090"
GRAFANA_API_KEY=""
GRAFANA_PORT="3000"
CROWDSEC_PORT="6060"
INSTALL_PIHOLE="y"
INSTALL_UNBOUND="y"
INSTALL_CROWDSEC="y"
INSTALL_PROMETHEUS="y"
INSTALL_GRAFANA="y"
UPDATE_SYSTEM="y"
INSTALL_PACKAGES="y"

HOST_IP=$(hostname -I | awk '{print $1}')
if [ -z "$HOST_IP" ]; then
  log_message "Błąd krytyczny: Nie można pobrać adresu IP hosta. Skrypt przerwany."
  exit 1
fi
log_message "Adres IP hosta: $HOST_IP"

read -p "Podaj port Prometheus (domyślnie $PROMETHEUS_PORT): " PROMETHEUS_PORT_INPUT
PROMETHEUS_PORT=${PROMETHEUS_PORT_INPUT:-$PROMETHEUS_PORT}
read -p "Podaj port Grafana (domyślnie $GRAFANA_PORT): " GRAFANA_PORT_INPUT
GRAFANA_PORT=${GRAFANA_PORT_INPUT:-$GRAFANA_PORT}
read -p "Podaj port Unbound (domyślnie $UNBOUND_PORT): " UNBOUND_PORT_INPUT
UNBOUND_PORT=${UNBOUND_PORT_INPUT:-$UNBOUND_PORT}
read -p "Podaj port metryk CrowdSec (domyślnie $CROWDSEC_PORT): " CROWDSEC_PORT_INPUT
CROWDSEC_PORT=${CROWDSEC_PORT_INPUT:-$CROWDSEC_PORT}

while true; do
  read -sp "Podaj hasło dla Pi-hole (min. 8 znaków): " PIHOLE_WEB_PASSWORD
  echo
  if [ ${#PIHOLE_WEB_PASSWORD} -ge 8 ]; then
    log_message "Hasło dla Pi-hole zostało pobrane."
    break
  else
    log_message "Hasło musi mieć co najmniej 8 znaków. Spróbuj ponownie."
  fi
done

function get_yes_no {
  local prompt=$1
  local default=$2
  while true; do
    read -p "$prompt (y/n) [$default]: " response
    response=${response:-$default}
    case "$response" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) log_message "Proszę wpisać 'y' lub 'n'." ;;
    esac
  done
}

get_yes_no "Zainstalować Pi-hole?" "y" && INSTALL_PIHOLE="y" || INSTALL_PIHOLE="n"
get_yes_no "Zainstalować Unbound?" "y" && INSTALL_UNBOUND="y" || INSTALL_UNBOUND="n"
get_yes_no "Zainstalować CrowdSec?" "y" && INSTALL_CROWDSEC="y" || INSTALL_CROWDSEC="n"
get_yes_no "Zainstalować Prometheus?" "y" && INSTALL_PROMETHEUS="y" || INSTALL_PROMETHEUS="n"
get_yes_no "Zainstalować Grafana?" "y" && INSTALL_GRAFANA="y" || INSTALL_GRAFANA="n"
get_yes_no "Aktualizować system?" "y" && UPDATE_SYSTEM="y" || UPDATE_SYSTEM="n"
get_yes_no "Zainstalować wymagane pakiety?" "y" && INSTALL_PACKAGES="y" || INSTALL_PACKAGES="n"

if [ "$UPDATE_SYSTEM" == "y" ]; then
  log_message "Aktualizacja systemu..."
  exec_cmd "aktualizacja systemu" apt update && apt upgrade -y
fi

if [ "$INSTALL_PACKAGES" == "y" ]; then
  log_message "Instalacja wymaganych pakietów..."
  install_package wget
  install_package curl
  install_package git
  install_package apt-transport-https
  install_package software-properties-common
  install_package dnsutils
fi

if [ "$INSTALL_PIHOLE" == "y" ]; then
  check_port_availability 80 "Pi-hole Web" || exit 1
  check_port_availability 443 "Pi-hole Web (HTTPS)" || exit 1
fi
if [ "$INSTALL_UNBOUND" == "y" ]; then
  check_port_availability "$UNBOUND_PORT" "Unbound" || exit 1
fi
if [ "$INSTALL_PROMETHEUS" == "y" ]; then
  check_port_availability "$PROMETHEUS_PORT" "Prometheus" || exit 1
fi
if [ "$INSTALL_GRAFANA" == "y" ]; then
  check_port_availability "$GRAFANA_PORT" "Grafana" || exit 1
fi
if [ "$INSTALL_CROWDSEC" == "y" ]; then
  check_port_availability "$CROWDSEC_PORT" "CrowdSec Metrics" || exit 1
fi

test_network

# -----------------------------------------------------------------------------
# Instalacja CrowdSec
# -----------------------------------------------------------------------------
if [ "$INSTALL_CROWDSEC" == "y" ]; then
  log_message "Instalacja CrowdSec bez rejestracji API..."
  if ! curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh -o /tmp/crowdsec_script.deb.sh; then
    log_message "Błąd: Pobieranie skryptu instalacyjnego CrowdSec nie powiodło się."
    if [ $(get_error_action "Co zrobić po błędzie pobierania skryptu CrowdSec?") -eq 0 ]; then
      log_message "Skrypt przerwany na życzenie użytkownika."
      exit 1
    else
      log_message "Pominięto instalację CrowdSec."
    fi
  else
    bash /tmp/crowdsec_script.deb.sh
    install_package crowdsec
    install_package crowdsec-firewall-bouncer-iptables

    log_message "Konfiguracja CrowdSec (tryb lokalny, bez API)..."
    CONFIG_FILE="/etc/crowdsec/config.yaml"
    if [ -f "$CONFIG_FILE" ]; then
      if grep -q "api:" "$CONFIG_FILE"; then
        sed -i '/api:/,/^$/ { /client:/,/^$/ s/disabled: false/disabled: true/ }' "$CONFIG_FILE"
      else
        echo -e "\napi:\n  client:\n    disabled: true" >> "$CONFIG_FILE"
      fi
      log_message "Konfiguracja CrowdSec zaktualizowana."
    else
      log_message "Błąd krytyczny: Brak pliku $CONFIG_FILE."
      if [ $(get_error_action "Co zrobić, gdy brak pliku konfiguracyjnego CrowdSec?") -eq 0 ]; then
        log_message "Skrypt przerwany na życzenie użytkownika."
        exit 1
      else
        log_message "Pominięto konfigurację CrowdSec."
      fi
    fi

    if ! cscli collections install crowdsecurity/sshd; then
      log_message "Błąd: Instalacja kolekcji sshd nie powiodła się."
      if [ $(get_error_action "Co zrobić po błędzie instalacji kolekcji sshd?") -eq 0 ]; then
        log_message "Skrypt przerwany na życzenie użytkownika."
        exit 1
      else
        log_message "Pominięto instalację kolekcji sshd."
      fi
    fi

    enable_and_start_service crowdsec
    enable_and_start_service crowdsec-firewall-bouncer

    if [ -f "$CONFIG_FILE" ]; then
      if grep -q "prometheus:" "$CONFIG_FILE"; then
        sed -i "s/enabled: false/enabled: true/" "$CONFIG_FILE"
      else
        echo -e "\nprometheus:\n  enabled: true\n  listen_addr: 0.0.0.0\n  listen_port: $CROWDSEC_PORT" >> "$CONFIG_FILE"
      fi
      systemctl restart crowdsec
      log_message "Metryki Prometheus włączone dla CrowdSec."
    fi

    test_connection curl "http://localhost:$CROWDSEC_PORT/metrics" "CrowdSec Metrics"
    rm -f /tmp/crowdsec_script.deb.sh
  fi
fi

# -----------------------------------------------------------------------------
# Instalacja Pi-hole
# -----------------------------------------------------------------------------
if [ "$INSTALL_PIHOLE" == "y" ]; then
  log_message "Instalacja Pi-hole w trybie nienadzorowanym..."
  if ! curl -sSL https://install.pi-hole.net -o /tmp/pihole_install.sh; then
    log_message "Błąd: Pobieranie skryptu instalacyjnego Pi-hole nie powiodło się."
    if [ $(get_error_action "Co zrobić po błędzie pobierania skryptu Pi-hole?") -eq 0 ]; then
      log_message "Skrypt przerwany na życzenie użytkownika."
      exit 1
    else
      log_message "Pominięto instalację Pi-hole."
    fi
  else
    if ! bash /tmp/pihole_install.sh --unattended adminpw="$PIHOLE_WEB_PASSWORD"; then
      log_message "Błąd: Instalacja Pi-hole nie powiodła się."
      if [ $(get_error_action "Co zrobić po błędzie instalacji Pi-hole?") -eq 0 ]; then
        log_message "Skrypt przerwany na życzenie użytkownika."
        exit 1
      else
        log_message "Pominięto instalację Pi-hole."
      fi
    else
      log_message "Pi-hole zainstalowany."
      rm -f /tmp/pihole_install.sh
    fi
  fi
fi

# -----------------------------------------------------------------------------
# Instalacja i konfiguracja Unbound
# -----------------------------------------------------------------------------
if [ "$INSTALL_UNBOUND" == "y" ]; then
  log_message "Konfiguracja Unbound..."
  install_package unbound

  sysctl -w net.core.rmem_max=4194304 2>/dev/null
  sysctl -w net.core.rmem_default=4194304 2>/dev/null
  echo "net.core.rmem_max=4194304" >> /etc/sysctl.conf 2>/dev/null
  echo "net.core.rmem_default=4194304" >> /etc/sysctl.conf 2>/dev/null

  mkdir -p /var/log/unbound
  touch /var/log/unbound/unbound.log
  chown -R unbound:unbound /var/log/unbound
  chmod 755 /var/log/unbound
  chmod 644 /var/log/unbound/unbound.log
  log_message "Uprawnienia /var/log/unbound: $(ls -ld /var/log/unbound)"
  log_message "Uprawnienia /var/log/unbound/unbound.log: $(ls -l /var/log/unbound/unbound.log)"

  UNBOUND_CONFIG=$(cat <<EOF
server:
  logfile: "/var/log/unbound/unbound.log"
  verbosity: 1
  interface: $UNBOUND_IP
  port: $UNBOUND_PORT
  do-ip4: yes
  do-udp: yes
  do-tcp: yes
  do-ip6: no
  do-daemonize: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  use-caps-for-id: no
  edns-buffer-size: 1472
  prefetch: yes
  num-threads: 1
  so-rcvbuf: 4m
  hide-identity: yes
  hide-version: yes
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
EOF
)
  create_config_file_if_not_exists "/etc/unbound/unbound.conf.d/pi-hole.conf" "$UNBOUND_CONFIG" "Unbound"
  enable_and_start_service unbound

  if [ "$INSTALL_PIHOLE" == "y" ]; then
    log_message "Konfiguracja Pi-hole do używania Unbound..."
    pihole -a -d "$UNBOUND_IP#$UNBOUND_PORT"
    pihole restartdns
  fi

  test_connection dig "$UNBOUND_IP@$UNBOUND_PORT" "Unbound"
fi

# -----------------------------------------------------------------------------
# Instalacja Prometheus
# -----------------------------------------------------------------------------
if [ "$INSTALL_PROMETHEUS" == "y" ]; then
  log_message "Instalacja Prometheus wersji $PROMETHEUS_VERSION..."
  if ! wget "https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz" -O /tmp/prometheus.tar.gz; then
    log_message "Błąd: Pobieranie Prometheus nie powiodło się."
    if [ $(get_error_action "Co zrobić po błędzie pobierania Prometheus?") -eq 0 ];then
      log_message "Skrypt przerwany na życzenie użytkownika."
      exit 1
    else
      log_message "Pominięto instalację Prometheus."
    fi
  else
    tar xvf /tmp/prometheus.tar.gz -C /tmp/ 2>/dev/null
    cd /tmp/prometheus-${PROMETHEUS_VERSION}.linux-amd64
    mv prometheus promtool /usr/local/bin/
    mkdir -p /etc/prometheus /var/lib/prometheus
    mv prometheus.yml /etc/prometheus/

    PROMETHEUS_SYSTEMD_CONFIG=$(cat <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \\
    --config.file=/etc/prometheus/prometheus.yml \\
    --storage.tsdb.path=/var/lib/prometheus/

[Install]
WantedBy=multi-user.target
EOF
)
    create_config_file_if_not_exists "/etc/systemd/system/prometheus.service" "$PROMETHEUS_SYSTEMD_CONFIG" "Prometheus systemd service"

    useradd --no-create-home --shell /bin/false prometheus 2>/dev/null
    chown -R prometheus:prometheus /var/lib/prometheus /etc/prometheus/prometheus.yml

    if [ "$INSTALL_CROWDSEC" == "y" ]; then
      log_message "Konfiguracja Prometheus do zbierania metryk CrowdSec..."
      if grep -q "^scrape_configs:" /etc/prometheus/prometheus.yml; then
        sed -i '/^scrape_configs:/a \
  - job_name: "crowdsec"\
    static_configs:\
      - targets: ["localhost:'"$CROWDSEC_PORT"'"]' /etc/prometheus/prometheus.yml
      else
        echo -e "scrape_configs:\n  - job_name: \"crowdsec\"\n    static_configs:\n      - targets: [\"localhost:$CROWDSEC_PORT\"]" >> /etc/prometheus/prometheus.yml
      fi
    fi

    enable_and_start_service prometheus
    rm -rf /tmp/prometheus-${PROMETHEUS_VERSION}.linux-amd64 /tmp/prometheus.tar.gz
  fi
fi

# -----------------------------------------------------------------------------
# Instalacja Grafana
# -----------------------------------------------------------------------------
if [ "$INSTALL_GRAFANA" == "y" ]; then
  log_message "Instalacja Grafana..."
  install_package wget
  install_package gpg
  if ! wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor -o /usr/share/keyrings/grafana-archive-keyring.gpg; then
    log_message "Błąd: Pobieranie klucza GPG Grafana nie powiodło się."
    if [ $(get_error_action "Co zrobić po błędzie pobierania klucza GPG Grafana?") -eq 0 ]; then
      log_message "Skrypt przerwany na życzenie użytkownika."
      exit 1
    else
      log_message "Pominięto instalację Grafana."
    fi
  else
    if ! echo "deb [signed-by=/usr/share/keyrings/grafana-archive-keyring.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list; then
      log_message "Błąd: Dodawanie repozytorium Grafana nie powiodło się."
      if [ $(get_error_action "Co zrobić po błędzie dodawania repozytorium Grafana?") -eq 0 ]; then
        log_message "Skrypt przerwany na życzenie użytkownika."
        exit 1
      else
        log_message "Pominięto dodawanie repozytorium Grafana."
      fi
    else
      apt update
      install_package grafana
      enable_and_start_service grafana-server
    fi
  fi
fi

# -----------------------------------------------------------------------------
# Konfiguracja UFW i zakończenie
# -----------------------------------------------------------------------------
log_message "Konfiguracja UFW..."
ufw default deny incoming 2>/dev/null
ufw default allow outgoing 2>/dev/null
configure_ufw 22 "SSH"
configure_ufw 53 "DNS"
[ "$INSTALL_PIHOLE" == "y" ] && { configure_ufw 80 "Pi-hole Web"; configure_ufw 443 "Pi-hole Web (HTTPS)"; }
[ "$INSTALL_UNBOUND" == "y" ] && configure_ufw "$UNBOUND_PORT" "Unbound"
[ "$INSTALL_GRAFANA" == "y" ] && configure_ufw "$GRAFANA_PORT" "Grafana"
[ "$INSTALL_PROMETHEUS" == "y" ] && configure_ufw "$PROMETHEUS_PORT" "Prometheus"
[ "$INSTALL_CROWDSEC" == "y" ] && configure_ufw "$CROWDSEC_PORT" "CrowdSec Metrics"

if ! ufw enable -f; then
  log_message "Błąd: Włączanie UFW nie powiodło się."
  if [ $(get_error_action "Co zrobić po błędzie włączania UFW?") -eq 0 ]; then
    log_message "Skrypt przerwany na życzenie użytkownika."
    exit 1
  else
    log_message "Pominięto włączanie UFW."
  fi
else
  ufw status verbose
fi

log_message "Skrypt zakończony. Sprawdź logi w /var/log/install_script.log."
log_message "CrowdSec skonfigurowany w trybie lokalnym bez rejestracji API."
log_message "Grafana i Prometheus dostępne są pod: http://${HOST_IP}:$GRAFANA_PORT (Grafana) oraz http://${HOST_IP}:$PROMETHEUS_PORT (Prometheus)."
