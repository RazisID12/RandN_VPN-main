#!/bin/bash
# DOWN-script RandN_Server-main (снимает ровно то, что ставит UP-script)
exec 2>/dev/null

# 1. Внешний интерфейс ────────────────────────────────────────────────────────
[[ -z "$1" ]] && INTERFACE="$(ip route | awk '/^default/{print $5;exit}')" || INTERFACE=$1
EXT_IP=95.164.123.146

# 2. NAT, поставленные UP-script ───────────────────────────────────────────────
for NET in \
    10.29.0.0/22 10.29.4.0/22 10.29.8.0/24 \
    172.29.0.0/22 172.29.4.0/22 172.29.8.0/24
do
    iptables -w -t nat -D PREROUTING -s "$NET" ! -d "$EXT_IP" -p udp --dport 53 -j DNAT --to-destination "$EXT_IP"
    iptables -w -t nat -D PREROUTING -s "$NET" ! -d "$EXT_IP" -p tcp --dport 53 -j DNAT --to-destination "$EXT_IP"
done
iptables -w -t nat -D POSTROUTING -s 10.29.0.0/16  -d "$EXT_IP"/32 -j MASQUERADE
iptables -w -t nat -D POSTROUTING -s 172.29.0.0/16 -d "$EXT_IP"/32 -j MASQUERADE

# Резервные порты OpenVPN / AmneziaWG
iptables -w -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 5080  -j REDIRECT --to-ports 50080
iptables -w -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 5443  -j REDIRECT --to-ports 50443
iptables -w -t nat -D PREROUTING -i "$INTERFACE" -p udp --dport 5080  -j REDIRECT --to-ports 50080
iptables -w -t nat -D PREROUTING -i "$INTERFACE" -p udp --dport 5443  -j REDIRECT --to-ports 50443
iptables -w -t nat -D PREROUTING -i "$INTERFACE" -p udp --dport 52080 -j REDIRECT --to-ports 51080
iptables -w -t nat -D PREROUTING -i "$INTERFACE" -p udp --dport 52443 -j REDIRECT --to-ports 51443

# RANDN_VPN-MAIN-MAPPING + общий MASQUERADE
iptables -w -t nat -D PREROUTING -s 10.29.0.0/16  -d 10.30.0.0/15  -j RANDN_VPN-MAIN-MAPPING
iptables -w -t nat -D PREROUTING -s 172.29.0.0/16 -d 172.30.0.0/15 -j RANDN_VPN-MAIN-MAPPING
iptables -w -t nat -D POSTROUTING -s 10.28.0.0/15  -j MASQUERADE
iptables -w -t nat -D POSTROUTING -s 172.28.0.0/15 -j MASQUERADE

# 3. INPUT-ACCEPT для DNS из VPN-сетей ─────────────────────────────────────────
for NET in 10.29.0.0/16 172.29.0.0/16; do
    iptables -w -D INPUT -s "$NET" -p udp --dport 53 -j ACCEPT
    iptables -w -D INPUT -s "$NET" -p tcp --dport 53 -j ACCEPT
done

# 4. Сервисные правила (инверсия UP-script) ────────────────────────────────────
iptables  -w -D INPUT  -i lo -j ACCEPT
iptables  -w -D OUTPUT -o lo -j ACCEPT
iptables  -w -D INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -w -D INPUT  -i lo -j ACCEPT
ip6tables -w -D OUTPUT -o lo -j ACCEPT
ip6tables -w -D INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# SSH и панели
for IP4 in 95.164.123.146 150.241.64.91 37.230.147.37; do
    iptables -w -D INPUT -p tcp --dport 22   -s "$IP4" -j ACCEPT
    iptables -w -D INPUT -p tcp --dport 300  -s "$IP4" -j ACCEPT
    iptables -w -D INPUT -p tcp --dport 3000 -s "$IP4" -j ACCEPT
done

# Certbot / DoH / DoT
for PORT in 80 443 853; do iptables -w -D INPUT -p tcp --dport $PORT -j ACCEPT; done
iptables -w -D INPUT -p udp --dport 443 -j ACCEPT
iptables -w -D INPUT -p udp --dport 853 -j ACCEPT

# DoH / DoT + ICMPv6
for PORT in 443 853; do
    ip6tables -w -D INPUT -p tcp --dport $PORT -j ACCEPT
    ip6tables -w -D INPUT -p udp --dport $PORT -j ACCEPT
done
for T in 133 134 135 136 143; do
    ip6tables -w -D INPUT -p icmpv6 --icmpv6-type $T -j ACCEPT
done
# дополнительные ICMPv6-типы
for T in 1 2 3 4 144 145; do
    ip6tables -w -D INPUT -p icmpv6 --icmpv6-type $T -j ACCEPT
done
# лимит на Echo-Reply 129
ip6tables -w -D INPUT -p icmpv6 --icmpv6-type 129 \
          -m limit --limit 4/second --limit-burst 20 -j ACCEPT

# VPN-порты
iptables -w -D INPUT -p udp --dport 51820 -j ACCEPT
for P in 50080 50443 51080 51443; do
    iptables -w -D INPUT -p udp --dport $P -j ACCEPT
    iptables -w -D INPUT -p tcp --dport $P -j ACCEPT
done

# Транзит VPN-подсетей
iptables -w -D FORWARD -s 10.28.0.0/15  -j ACCEPT
iptables -w -D FORWARD -d 10.28.0.0/15  -j ACCEPT
iptables -w -D FORWARD -s 172.28.0.0/15 -j ACCEPT
iptables -w -D FORWARD -d 172.28.0.0/15 -j ACCEPT

# ── 4-bis. Анти-скан / лимиты (удаляем) ──────────────────────────
iptables -w -D INPUT -p tcp --syn \
         -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP
iptables -w -D INPUT -p tcp --tcp-flags ALL NONE        -j DROP
iptables -w -D INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -w -D INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -w -D INPUT -p icmp --icmp-type echo-request \
         -m limit --limit 4/second --limit-burst 20 -j ACCEPT
# служебные ICMP-типы
iptables -w -D INPUT -p icmp --icmp-type 3 -j ACCEPT
iptables -w -D INPUT -p icmp --icmp-type 4 -j ACCEPT
iptables -w -D INPUT -i "$INTERFACE" -s 224.0.0.0/3   -j DROP
iptables -w -D INPUT -i "$INTERFACE" -s 169.254.0.0/16 -j DROP
iptables -w -D INPUT -s 127.0.0.0/8 ! -i lo -j DROP

# ── 4-bis-v6. Анти-скан / лимиты (удаляем) ──────────────────────
ip6tables -w -D INPUT -p tcp --syn \
          -m connlimit --connlimit-above 20 --connlimit-mask 128 -j DROP
ip6tables -w -D INPUT -p tcp --tcp-flags ALL NONE        -j DROP
ip6tables -w -D INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
ip6tables -w -D INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
ip6tables -w -D INPUT -p icmpv6 --icmpv6-type 128 \
          -m limit --limit 4/second --limit-burst 20 -j ACCEPT
ip6tables -w -D INPUT -i "$INTERFACE" -s ff00::/8  -j DROP
ip6tables -w -D INPUT -i "$INTERFACE" -s fe80::/10 -j DROP
ip6tables -w -D INPUT -s ::1/128 ! -i lo -j DROP

# 5. Финальные DROP-строки ───────────────────────────────────────
iptables  -w -D INPUT -j DROP
ip6tables -w -D INPUT -j DROP

# 6. Fail2Ban и ipset-DROP ───────────────────────────────────────
for CH in f2b-sshd f2b-adguard-panel f2b-recidive; do
    iptables  -w -D INPUT -j "$CH" 2>/dev/null || true
    ip6tables -w -D INPUT -j "$CH" 2>/dev/null || true
done
iptables  -w -D INPUT -m set --match-set ipset-block  src -j DROP 2>/dev/null || true
ip6tables -w -D INPUT -m set --match-set ipset-block6 src -j DROP 2>/dev/null || true

# 7. Базовая гигиена ─────────────────────────────────────────────
iptables -w -D INPUT   -m conntrack --ctstate INVALID -j DROP
iptables -w -D FORWARD -m conntrack --ctstate INVALID -j DROP
iptables -w -D OUTPUT  -m conntrack --ctstate INVALID -j DROP
ip6tables -w -D INPUT   -m conntrack --ctstate INVALID -j DROP
ip6tables -w -D FORWARD -m conntrack --ctstate INVALID -j DROP
ip6tables -w -D OUTPUT  -m conntrack --ctstate INVALID -j DROP

# 8. Возврат политик цепей в ACCEPT ──────────────────────────────
iptables  -w -P INPUT   ACCEPT
iptables  -w -P FORWARD ACCEPT
iptables  -w -P OUTPUT  ACCEPT
ip6tables -w -P INPUT   ACCEPT
ip6tables -w -P FORWARD ACCEPT
ip6tables -w -P OUTPUT  ACCEPT

# 9-bis. Сохранение ipset-банов перед остановкой ────────────────
mkdir -p /var/lib/ipset
IPSET_STATE=/var/lib/ipset/ipset-bans.rules
ipset save -file "$IPSET_STATE"

# 9. Кастомный хук ───────────────────────────────────────────────
/opt/randn_vpn-main/custom-down.sh
