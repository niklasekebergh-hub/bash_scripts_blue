#!/usr/bin/env bash
set -euo pipefail

TIMEOUT_SECS=4          # per-command timeout when possible
MAX_GREP_HITS=300       # per-grep cap
MAX_FIND_FILES=6000     # per-root file listing cap
MAX_RECENT=250          # per-root recent file changes cap
MAX_INTERESTING=250     # per-root interesting file types cap
MAX_CONFIG_DUMP=1400    # max lines of nginx -T printed
MAX_PS=250              # max lines of process grep
MAX_JOURNAL=300         # max lines per journalctl query


ts() { date +"%Y-%m-%d %H:%M:%S %Z"; }
hr() { printf '\n%s\n' "================================================================================"; }
h1() { hr; printf '%s\n' "$1"; hr; }
h2() { printf '\n--- %s ---\n' "$1"; }

need_cmd() { command -v "$1" >/dev/null 2>&1; }

timeout_cmd() {
  if need_cmd timeout; then
    timeout "${TIMEOUT_SECS}" "$@"
  else
    "$@"
  fi
}

run() {
  local title="$1"; shift
  h2 "$title"
  ( set +e; timeout_cmd "$@" ) 2>&1 | sed 's/\r$//'
  return 0
}

# ---------------- header ----------------
h1 "WEB TRIAGE — $(hostname) — $(ts)"
echo "user: $(id -un) uid=$(id -u) groups=$(id -Gn)"
echo "kernel: $(uname -r)"
if [ -f /etc/os-release ]; then
  echo "os: $(. /etc/os-release; echo "${PRETTY_NAME:-$NAME $VERSION}")"
else
  echo "os: unknown"
fi
echo "cwd: $(pwd)"
echo "uptime: $(uptime -p 2>/dev/null || true)"

# --------------- 1) listeners + net ---------------
h1 "1) LISTENERS / NETWORK (what is exposed?)"
run "Listeners (ss -tulpen)" ss -tulpen
run "IPs / routes" bash -lc 'ip -br a; echo; ip r; echo; ip -br link'

if need_cmd nft; then
  run "Firewall (nft ruleset — first 250 lines)" bash -lc 'nft list ruleset 2>/dev/null | head -n 250'
fi
if need_cmd iptables; then
  run "Firewall (iptables filter)" iptables -S
  run "Firewall (iptables nat)" iptables -t nat -S
fi
if need_cmd ufw; then
  run "Firewall (ufw status verbose)" ufw status verbose
fi
if need_cmd firewall-cmd; then
  run "Firewall (firewalld state)" firewall-cmd --state
  run "Firewall (firewalld active zones)" firewall-cmd --get-active-zones
fi

# --------------- 2) services + processes ---------------
h1 "2) SERVICES / PROCESSES (what web stack exists?)"
if need_cmd systemctl; then
  run "Running services (top 200)" bash -lc 'systemctl --no-pager --type=service --state=running | head -n 200'
  run "Web-ish services (grep)" bash -lc 'systemctl --no-pager --type=service --all | grep -Ei "(nginx|apache2|httpd|caddy|lighttpd|traefik|haproxy|varnish|tomcat|jetty|gunicorn|uwsgi|php-fpm|node|pm2|docker|podman|redis|postgres|mysql|mariadb|mongodb|elasticsearch|kibana|grafana)" | head -n 300 || true'
fi

run "Web-ish processes (ps grep; top ${MAX_PS})" bash -lc \
  "ps auxwww | grep -Ei \"(nginx|apache2|httpd|caddy|lighttpd|traefik|haproxy|varnish|tomcat|jetty|gunicorn|uwsgi|php-fpm|node|pm2|rails|puma|unicorn|dotnet|kestrel|spring|flask|django)\" | grep -v grep | head -n ${MAX_PS} || true"

# --------------- 3) web server config visibility ---------------
h1 "3) WEB SERVER / PROXY CONFIGS (vhosts, proxies, docroots, modules)"

# NGINX
if need_cmd nginx; then
  run "nginx -v" nginx -v
  run "nginx -T (first ${MAX_CONFIG_DUMP} lines)" bash -lc "timeout_cmd nginx -T 2>&1 | sed -n '1,${MAX_CONFIG_DUMP}p'"
else
  [ -d /etc/nginx ] && run "/etc/nginx exists — list key dirs" bash -lc 'ls -la /etc/nginx; echo; ls -la /etc/nginx/sites-enabled 2>/dev/null || true; ls -la /etc/nginx/conf.d 2>/dev/null || true'
fi

# APACHE
if need_cmd apachectl; then
  run "apachectl -v" apachectl -v
  run "apachectl -S (vhosts)" apachectl -S
  run "apachectl -M (modules; first 220 lines)" bash -lc 'apachectl -M 2>&1 | head -n 220'
elif need_cmd httpd; then
  run "httpd -v" httpd -v
  run "httpd -S (vhosts)" httpd -S
fi

[ -d /etc/apache2 ] && run "/etc/apache2 sites-enabled + ports.conf" bash -lc 'ls -la /etc/apache2/sites-enabled 2>/dev/null || true; echo; sed -n "1,200p" /etc/apache2/ports.conf 2>/dev/null || true'
[ -d /etc/httpd ] && run "/etc/httpd conf.d listing" bash -lc 'ls -la /etc/httpd; echo; ls -la /etc/httpd/conf.d 2>/dev/null || true'

# CADDY / LIGHTTPD / HAPROXY / TRAEFIK
if need_cmd caddy; then
  run "caddy version" caddy version
  run "Caddyfile paths" bash -lc 'ls -la /etc/caddy 2>/dev/null || true; ls -la /etc/caddy/Caddyfile 2>/dev/null || true'
fi
if need_cmd lighttpd; then
  run "lighttpd -v" lighttpd -v
  run "lighttpd configs" bash -lc 'ls -la /etc/lighttpd 2>/dev/null || true; ls -la /etc/lighttpd/conf-enabled 2>/dev/null || true'
fi
if need_cmd haproxy; then
  run "haproxy version (short)" bash -lc 'haproxy -vv 2>/dev/null | head -n 60 || true'
  run "haproxy.cfg (first 240 lines)" bash -lc 'sed -n "1,240p" /etc/haproxy/haproxy.cfg 2>/dev/null || true'
fi
if need_cmd traefik; then
  run "traefik version" traefik version 2>/dev/null || true
  run "traefik config paths" bash -lc 'ls -la /etc/traefik 2>/dev/null || true; ls -la /etc/traefik/traefik.y*ml 2>/dev/null || true'
fi

# PHP-FPM
if need_cmd php-fpm; then
  run "php-fpm -v" php-fpm -v
fi
[ -d /etc/php ] && run "/etc/php (php-fpm pools often here)" bash -lc 'find /etc/php -maxdepth 3 -type f -name "*.conf" 2>/dev/null | grep -Ei "(fpm|pool|php-fpm)" | head -n 200 || true'

# --------------- 4) docroot/app root discovery ---------------
h1 "4) DOCROOT / APP ROOT DISCOVERY (where content lives?)"

declare -a ROOTS=()
add_root() {
  local p="$1"
  [ -d "$p" ] || return 0
  for r in "${ROOTS[@]:-}"; do [ "$r" = "$p" ] && return 0; done
  ROOTS+=("$p")
}

# Common defaults
add_root /var/www
add_root /var/www/html
add_root /srv/www
add_root /usr/share/nginx/html
add_root /usr/local/www
add_root /opt

# Parse nginx -T for root directives
if need_cmd nginx; then
  while IFS= read -r line; do
    p="$(printf '%s' "$line" | sed -nE 's/^[[:space:]]*root[[:space:]]+([^;]+);.*/\1/p')"
    [ -n "$p" ] && add_root "$p"
  done < <(timeout_cmd nginx -T 2>/dev/null | head -n 12000 || true)
fi

# Parse Apache config files for DocumentRoot
for f in /etc/apache2/sites-enabled/* /etc/apache2/sites-available/* /etc/httpd/conf.d/* /etc/httpd/conf/*; do
  [ -f "$f" ] || continue
  while IFS= read -r dr; do
    p="$(printf '%s' "$dr" | awk '{print $2}' | tr -d '"')"
    [ -n "$p" ] && add_root "$p"
  done < <(grep -RInhE '^[[:space:]]*DocumentRoot[[:space:]]+' "$f" 2>/dev/null || true)
done

if [ "${#ROOTS[@]}" -eq 0 ]; then
  echo "No obvious docroots found."
else
  echo "Candidate roots:"
  for r in "${ROOTS[@]}"; do echo "  - $r"; done
fi

# --------------- 5) surface inventory (bounded) ---------------
h1 "5) SURFACE INVENTORY (files/endpoints, recent changes, risky stuff)"

interesting_find() {
  local r="$1"
  find "$r" -xdev -type f \( \
    -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.asp' -o -iname '*.aspx' \
    -o -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.cgi' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.rb' \
    -o -iname '*.js' -o -iname '*.ts' -o -iname '*.html' -o -iname '*.htm' -o -iname '*.jar' -o -iname '*.war' -o -iname '*.ear' \
  \) -printf '%TY-%Tm-%Td %TH:%TM %u:%g %p\n' 2>/dev/null
}

for r in "${ROOTS[@]}"; do
  [ -d "$r" ] || continue
  h2 "ROOT: $r"
  echo "perms: $(stat -c '%A %U:%G %n' "$r" 2>/dev/null || echo 'stat failed')"
  echo "top entries:"
  ls -la "$r" 2>/dev/null | head -n 50 || true

  run "Interesting web/app files (newest first; top ${MAX_INTERESTING})" bash -lc \
    "interesting_find \"$r\" | sort -r | head -n ${MAX_INTERESTING}"

  run "Recent changes (mtime < 24h; newest first; top ${MAX_RECENT})" bash -lc \
    "find \"$r\" -xdev -type f -mtime -1 -printf '%TY-%Tm-%Td %TH:%TM %u:%g %p\n' 2>/dev/null | sort -r | head -n ${MAX_RECENT}"

  run "File path listing (capped ${MAX_FIND_FILES})" bash -lc \
    "find \"$r\" -xdev -type f 2>/dev/null | head -n ${MAX_FIND_FILES}"
done

# --------------- 6) config greps (high signal) ---------------
h1 "6) CONFIG HOTSPOTS (reverse proxy, admin panels, autoindex, allow-all)"

CFG_PATHS=(/etc/nginx /etc/apache2 /etc/httpd /etc/caddy /etc/lighttpd /etc/haproxy /etc/traefik)

grep_cap() {
  local label="$1"; shift
  local pat="$1"; shift
  h2 "$label"
  echo "pattern: $pat"
  for p in "${CFG_PATHS[@]}"; do
    [ -e "$p" ] || continue
    echo "==> $p"
    grep -RInE --binary-files=without-match "$pat" "$p" 2>/dev/null | head -n "$MAX_GREP_HITS" || true
  done
}

grep_cap "Reverse proxy / upstreams" '(proxy_pass|ProxyPass|fastcgi_pass|uwsgi_pass|grpc_pass|upstream[[:space:]]+|balancer://|PassReverse)'
grep_cap "Admin/status/debug-ish endpoints" '(server-status|stub_status|phpinfo|/debug|/admin|/manage|/console|/actuator|/metrics|/prometheus|/swagger|/graphql|/jenkins|/grafana|/kibana|/phpmyadmin|/pma)'
grep_cap "Autoindex / directory listing enabled" '(autoindex[[:space:]]+on|Options[[:space:]]+.*Indexes)'
grep_cap "Allow-all / Require granted / satisfy any" '(allow[[:space:]]+all|Require[[:space:]]+all[[:space:]]+granted|satisfy[[:space:]]+any)'

# --------------- 7) sensitive files + webshell heuristics ---------------
h1 "7) SENSITIVE FILES + SUSPICIOUS CODE (filesystem leads)"

SENSITIVE_PAT='(\.git/|/\.git$|\.env$|\.pem$|id_rsa|id_ed25519|\.bak$|\.old$|\.swp$|~$|backup|dump|\.sql$|\.sqlite$|\.db$|composer\.lock$|package-lock\.json$|yarn\.lock$|web\.config\.bak$|\.DS_Store$)'
SHELL_PAT='(eval\(|base64_decode\(|gzinflate\(|shell_exec\(|passthru\(|system\(|proc_open\(|popen\(|assert\(|\$_(GET|POST|REQUEST)\[)'

for r in "${ROOTS[@]}"; do
  [ -d "$r" ] || continue
  h2 "Sensitive filenames under $r (top 200)"
  find "$r" -xdev -type f 2>/dev/null | grep -E "$SENSITIVE_PAT" | head -n 200 || true

  h2 "Suspicious code patterns under $r (top ${MAX_GREP_HITS})"
  grep -RInE --binary-files=without-match \
    --include='*.php' --include='*.phtml' --include='*.asp' --include='*.aspx' --include='*.jsp' --include='*.jspx' \
    --include='*.js' --include='*.py' --include='*.pl' --include='*.rb' \
    "$SHELL_PAT" "$r" 2>/dev/null | head -n "$MAX_GREP_HITS" || true
done

# --------------- 8) TLS/certs ---------------
h1 "8) TLS / CERTS (what certs exist + expiry of referenced certs)"

if need_cmd openssl; then
  for d in /etc/letsencrypt /etc/ssl /usr/local/etc/ssl /var/lib/acme; do
    [ -d "$d" ] || continue
    h2 "Cert directory: $d (top 120 entries)"
    ls -la "$d" 2>/dev/null | head -n 120 || true
  done
fi

declare -a CERTS=()
add_cert() { local p="$1"; [ -f "$p" ] || return 0; for c in "${CERTS[@]:-}"; do [ "$c" = "$p" ] && return 0; done; CERTS+=("$p"); }

if need_cmd nginx; then
  while IFS= read -r line; do
    p="$(printf '%s' "$line" | sed -nE 's/^[[:space:]]*ssl_certificate[[:space:]]+([^;]+);.*/\1/p')"
    [ -n "$p" ] && add_cert "$p"
  done < <(timeout_cmd nginx -T 2>/dev/null | head -n 12000 || true)
fi
for f in /etc/apache2/sites-enabled/* /etc/apache2/sites-available/* /etc/httpd/conf.d/* /etc/httpd/conf/*; do
  [ -f "$f" ] || continue
  while IFS= read -r line; do
    p="$(printf '%s' "$line" | sed -nE 's/^[[:space:]]*SSLCertificateFile[[:space:]]+(.+)/\1/p' | tr -d '"')"
    [ -n "$p" ] && add_cert "$p"
  done < <(grep -RInhE '^[[:space:]]*SSLCertificateFile[[:space:]]+' "$f" 2>/dev/null || true)
done

if [ "${#CERTS[@]}" -eq 0 ]; then
  echo "No cert paths extracted from configs."
else
  h2 "Referenced certificate expiry"
  for c in "${CERTS[@]}"; do
    echo "==> $c"
    if need_cmd openssl; then
      openssl x509 -in "$c" -noout -subject -issuer -dates 2>/dev/null || echo "  openssl failed (not PEM x509?)"
    else
      echo "  openssl not installed"
    fi
  done
fi

# --------------- 9) localhost probes (safe) ---------------
h1 "9) LOCALHOST HTTP(S) PROBES (quick curl HEAD)"

if need_cmd curl; then
  PORTS="$(ss -tulpen 2>/dev/null | awk '/LISTEN/ && $5 ~ /:[0-9]+$/ {print $5}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -n | uniq)"
  echo "Detected listener ports:"
  echo "$PORTS" | tr '\n' ' '; echo

  CANDIDATES="$(printf '%s\n' 80 443 8080 8443 8000 8008 8888 5000 3000 3001 9090 9200 5601 15672 1880 2375 2376; echo "$PORTS")"
  CANDIDATES="$(printf '%s\n' $CANDIDATES | awk '$1 ~ /^[0-9]+$/ {print $1}' | sort -n | uniq)"

  while IFS= read -r p; do
    [ -n "$p" ] || continue
    proto="http"
    if [ "$p" = "443" ] || [ "$p" = "8443" ]; then proto="https"; fi
    h2 "curl ${proto}://127.0.0.1:${p}/ (HEAD; timeout ${TIMEOUT_SECS}s)"
    timeout_cmd curl -skI --max-time "$TIMEOUT_SECS" "${proto}://127.0.0.1:${p}/" | sed -n '1,25p' || true
  done <<< "$CANDIDATES"
else
  echo "curl not installed; skipping."
fi

# --------------- 10) containers ---------------
h1 "10) CONTAINERS (docker/podman quick view)"

if need_cmd docker; then
  run "docker ps (no-trunc)" docker ps --no-trunc
  run "docker ports view" bash -lc 'docker ps --format "table {{.Names}}\t{{.Ports}}" 2>/dev/null || true'
  run "docker compose list" bash -lc 'docker compose ls 2>/dev/null || true'
fi
if need_cmd podman; then
  run "podman ps (no-trunc)" podman ps --no-trunc
fi

# --------------- 11) quick logs ---------------
h1 "11) LOG QUICKLOOK (last few minutes)"

if need_cmd journalctl; then
  run "journalctl nginx (last 10m; cap ${MAX_JOURNAL})" bash -lc "journalctl -u nginx --since '10 min ago' 2>/dev/null | tail -n ${MAX_JOURNAL} || true"
  run "journalctl apache2 (last 10m; cap ${MAX_JOURNAL})" bash -lc "journalctl -u apache2 --since '10 min ago' 2>/dev/null | tail -n ${MAX_JOURNAL} || true"
  run "journalctl httpd (last 10m; cap ${MAX_JOURNAL})" bash -lc "journalctl -u httpd --since '10 min ago' 2>/dev/null | tail -n ${MAX_JOURNAL} || true"
  run "journalctl php-fpm (last 10m; cap ${MAX_JOURNAL})" bash -lc "journalctl -u php-fpm --since '10 min ago' 2>/dev/null | tail -n ${MAX_JOURNAL} || true"
fi

for f in /var/log/nginx/access.log /var/log/nginx/error.log /var/log/apache2/access.log /var/log/apache2/error.log /var/log/httpd/access_log /var/log/httpd/error_log; do
  [ -f "$f" ] || continue
  run "Tail $f (last 120 lines)" bash -lc "tail -n 120 \"$f\""
done

if [ -f /var/log/auth.log ]; then
  run "Auth log (last 120)" bash -lc 'tail -n 120 /var/log/auth.log'
elif [ -f /var/log/secure ]; then
  run "Secure log (last 120)" bash -lc 'tail -n 120 /var/log/secure'
fi

h1 "DONE — $(ts)"
echo "If you want a file, pipe it: sudo bash web_triage.sh | tee /root/web_triage_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
