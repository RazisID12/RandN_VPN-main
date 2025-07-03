#!/bin/bash
# UP-script RandN_VPN-main

# ── 1. Служебные опции ─────────────────────────────────────────────────────────
set -u
shopt -s expand_aliases
alias ipt='iptables -w'
alias ipt6='ip6tables -w'

ins()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null || ipt  -t "$t" -I "$c" 1 "$@"; }
ins6() { local t=$1 c=$2; shift 2; ipt6 -t "$t" -C "$c" "$@" 2>/dev/null || ipt6 -t "$t" -I "$c" 1 "$@"; }
add()  { local t=$1 c=$2; shift 2; ipt  -t "$t" -C "$c" "$@" 2>/dev/null || ipt  -t "$t" -A "$c"   "$@"; }

# ── 2. Переменные ──────────────────────────────────────────────────────────────
INTERFACE=$(ip route | awk '/^default/{print $5;exit}')
[[ -z "$INTERFACE" ]] && { echo 'Default interface not found'; exit 1; }

EXT_IP=217.144.186.104
source /opt/randn_vpn-main/setup            # даёт $ALTERNATIVE_IP
[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"

# ── 3. Очистка старых правил ───────────────────────────────────────────────────
/opt/randn_vpn-main/down.sh "$INTERFACE"

# ── 4. Твики ядра ──────────────────────────────────────────────────────────────
echo 'cache.clear()' | socat - /run/knot-resolver/control/1 || true
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw kernel.printk="3 4 1 3"
sysctl -qw net.core.default_qdisc=fq
sysctl -qw net.ipv4.tcp_congestion_control=bbr

# anti-spoof / redirect-hardening
sysctl -qw net.ipv4.conf.all.rp_filter=1
sysctl -qw net.ipv4.conf.default.rp_filter=1
sysctl -qw net.ipv4.conf.all.accept_redirects=0
sysctl -qw net.ipv4.conf.default.accept_redirects=0
sysctl -qw net.ipv4.conf.all.send_redirects=0
sysctl -qw net.ipv4.conf.default.send_redirects=0

# ── 5. ipset-block ─────────────────────────────────────────────────────────────
ipset create ipset-block  hash:ip family inet  timeout 0 -exist
ipset create ipset-block6 hash:ip family inet6 timeout 0 -exist

# 5-bis. Восстановление банов между перезагрузками
mkdir -p /var/lib/ipset
IPSET_STATE=/var/lib/ipset/ipset-bans.rules
if [[ -f "$IPSET_STATE" ]]; then
    ipset flush ipset-block  2>/dev/null || true
    ipset flush ipset-block6 2>/dev/null || true
    ipset restore -exist < "$IPSET_STATE" || true
fi

# ── 6. Базовая гигиена ─────────────────────────────────────────────────────────
for tbl in filter; do
  ins  $tbl INPUT   -m conntrack --ctstate INVALID -j DROP
  ins  $tbl FORWARD -m conntrack --ctstate INVALID -j DROP
  ins  $tbl OUTPUT  -m conntrack --ctstate INVALID -j DROP
done
ins6 filter INPUT   -m conntrack --ctstate INVALID -j DROP
ins6 filter FORWARD -m conntrack --ctstate INVALID -j DROP
ins6 filter OUTPUT  -m conntrack --ctstate INVALID -j DROP

# ── 7. Сервисные правила ───────────────────────────────────────────────────────
# Loopback / ESTABLISHED
ins filter INPUT  -i lo -j ACCEPT
ins filter OUTPUT -o lo -j ACCEPT
ins filter INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# SSH (только доверенные)
for IP4 in 217.144.186.104 150.241.64.91 37.230.147.37; do
  ins filter INPUT -p tcp --dport 22   -s $IP4 -j ACCEPT
done

# Панель AdGuard (только доверенные)
for IP4 in 217.144.186.104 150.241.64.91 37.230.147.37; do
  ins filter INPUT -p tcp --dport 300  -s $IP4 -j ACCEPT
done

# Preset-UI AdGuard (только доверенные)
for IP4 in 217.144.186.104 150.241.64.91 37.230.147.37; do
  ins filter INPUT -p tcp --dport 3000 -s $IP4 -j ACCEPT
done

# Certbot
ins filter INPUT -p tcp --dport 80 -j ACCEPT

# DoH / DoT
for PORT in 443 853; do
  ins filter INPUT -p tcp --dport $PORT -j ACCEPT
done
ins filter INPUT -p udp --dport 443 -j ACCEPT   # HTTP-3
ins filter INPUT -p udp --dport 853 -j ACCEPT   # DoQ

# VPN-порты
ins filter INPUT -p udp --dport 51820 -j ACCEPT              # WireGuard
for P in 50080 50443 51080 51443; do                         # OpenVPN / Amnezia
  ins filter INPUT -p udp --dport $P -j ACCEPT
  ins filter INPUT -p tcp --dport $P -j ACCEPT
done

# DNS только из VPN-сетей
for NET in 10.29.0.0/16 172.29.0.0/16; do
  ins filter INPUT -p udp --dport 53 -s $NET -j ACCEPT
  ins filter INPUT -p tcp --dport 53 -s $NET -j ACCEPT
done

# Транзит VPN-подсетей
ins filter FORWARD -s ${IP}.28.0.0/15 -j ACCEPT
ins filter FORWARD -d ${IP}.28.0.0/15 -j ACCEPT

# ── 8. Анти-скан / лимиты (v4) ────────────────────────────────────────────────
## 1) SYN-flood
ins filter INPUT -p tcp --syn \
      -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP

## 2) FIN/NULL/XMAS/SYN-RST
ins filter INPUT -p tcp --tcp-flags ALL NONE            -j DROP
ins filter INPUT -p tcp --tcp-flags ALL FIN,URG,PSH     -j DROP
ins filter INPUT -p tcp --tcp-flags SYN,RST SYN,RST     -j DROP

## 3) ICMP-echo limit
ins filter INPUT -p icmp --icmp-type echo-request \
      -m limit --limit 4/second --limit-burst 20 -j ACCEPT

## 3-bis) служебные ICMP-типы
ins filter INPUT -p icmp --icmp-type 3 -j ACCEPT   # Destination-Unreach
ins filter INPUT -p icmp --icmp-type 4 -j ACCEPT   # Source-Quench / PMTU

## 4) Anti-spoofing
ins filter INPUT -i "$INTERFACE" -s 224.0.0.0/3   -j DROP
ins filter INPUT -i "$INTERFACE" -s 169.254.0.0/16 -j DROP
ins filter INPUT -s 127.0.0.0/8 ! -i lo -j DROP

# ── 9. Анти-скан / лимиты (v6) ────────────────────────────────────────────────
## 1) SYN-flood
ins6 filter INPUT -p tcp --syn \
      -m connlimit --connlimit-above 20 --connlimit-mask 128 -j DROP

## 2) FIN/NULL/XMAS/SYN-RST
ins6 filter INPUT -p tcp --tcp-flags ALL NONE            -j DROP
ins6 filter INPUT -p tcp --tcp-flags ALL FIN,URG,PSH     -j DROP
ins6 filter INPUT -p tcp --tcp-flags SYN,RST SYN,RST     -j DROP

## 3) ICMPv6-echo limit
ins6 filter INPUT -p icmpv6 --icmpv6-type 128 \
      -m limit --limit 4/second --limit-burst 20 -j ACCEPT
ins6 filter INPUT -p icmpv6 --icmpv6-type 129 \
      -m limit --limit 4/second --limit-burst 20 -j ACCEPT

## 4) Anti-spoofing
ins6 filter INPUT -i "$INTERFACE" -s ff00::/8  -j DROP
ins6 filter INPUT -i "$INTERFACE" -s fe80::/10 -j DROP
ins6 filter INPUT -s ::1/128 ! -i lo -j DROP

# ── 9-bis. Минимально нужное для IPv6 ─────────────────────────────────────────
ins6 filter INPUT  -i lo -j ACCEPT
ins6 filter OUTPUT -o lo -j ACCEPT
ins6 filter INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# обязательные ICMPv6-типы стека
for T in 133 134 135 136 143; do ins6 filter INPUT -p icmpv6 --icmpv6-type $T -j ACCEPT; done
# служебные ICMPv6
for T in 1 2 3 4 144 145; do ins6 filter INPUT -p icmpv6 --icmpv6-type $T -j ACCEPT; done

for PORT in 443 853; do
  ins6 filter INPUT -p tcp --dport $PORT -j ACCEPT
done
ins6 filter INPUT -p udp --dport 443 -j ACCEPT
ins6 filter INPUT -p udp --dport 853 -j ACCEPT

# финальные политики
ipt  -A INPUT -j DROP
ipt  -P INPUT   DROP
ipt  -P FORWARD DROP
ipt  -P OUTPUT  ACCEPT

ipt6 -A INPUT -j DROP
ipt6 -P INPUT   DROP
ipt6 -P FORWARD DROP
ipt6 -P OUTPUT  ACCEPT

# ── 10. Fail2Ban и ipset-DROP ────────────────────────────────────────────────
for CH in f2b-sshd f2b-adguard-panel f2b-recidive; do
  if ipt  -t filter -nL "$CH" &>/dev/null; then ipt  -D INPUT -j "$CH" 2>/dev/null; ipt  -I INPUT 1 -j "$CH"; fi
  if ipt6 -t filter -nL "$CH" &>/dev/null; then ipt6 -D INPUT -j "$CH" 2>/dev/null; ipt6 -I INPUT 1 -j "$CH"; fi
done
ins  filter INPUT -m set --match-set ipset-block  src -j DROP
ins6 filter INPUT -m set --match-set ipset-block6 src -j DROP

# ── 11. NAT ────────────────────────────────────────────────────────────────────────────────
# Резервные порты OpenVPN / AmneziaWG
if [[ "$OPENVPN_5080_5443_TCP" == "y" ]]; then
  add nat PREROUTING -i "$INTERFACE" -p tcp --dport 5080 -j REDIRECT --to-ports 50080
  add nat PREROUTING -i "$INTERFACE" -p tcp --dport 5443 -j REDIRECT --to-ports 50443
fi
if [[ "$OPENVPN_5080_5443_UDP" == "y" ]]; then
  add nat PREROUTING -i "$INTERFACE" -p udp --dport 5080 -j REDIRECT --to-ports 50080
  add nat PREROUTING -i "$INTERFACE" -p udp --dport 5443 -j REDIRECT --to-ports 50443
fi
add nat PREROUTING -i "$INTERFACE" -p udp --dport 52080 -j REDIRECT --to-ports 51080
add nat PREROUTING -i "$INTERFACE" -p udp --dport 52443 -j REDIRECT --to-ports 51443

# DNAT DNS → AdGuard Home
for NET in ${IP}.29.0.0/22 ${IP}.29.4.0/22 ${IP}.29.8.0/24; do
  add nat PREROUTING -s "$NET" ! -d "$EXT_IP" -p udp --dport 53 -j DNAT --to-destination "$EXT_IP"
  add nat PREROUTING -s "$NET" ! -d "$EXT_IP" -p tcp --dport 53 -j DNAT --to-destination "$EXT_IP"
done
add nat POSTROUTING -s ${IP}.29.0.0/16 -d "$EXT_IP"/32 -j MASQUERADE

# RANDN_VPN-MAIN-MAPPING + общий MASQUERADE
ipt -t nat -C PREROUTING -s ${IP}.29.0.0/16 -d ${IP}.30.0.0/15 -j RANDN_VPN-MAIN-MAPPING 2>/dev/null || {
  ipt -t nat -N RANDN_VPN-MAIN-MAPPING 2>/dev/null || true
  ipt -t nat -A PREROUTING -s ${IP}.29.0.0/16 -d ${IP}.30.0.0/15 -j RANDN_VPN-MAIN-MAPPING
}
add nat POSTROUTING -s ${IP}.28.0.0/15 -j MASQUERADE

# ── 12. Кастомный хук ───────────────────────────────────────────────────────────────────────
/opt/randn_vpn-main/custom-up.sh
