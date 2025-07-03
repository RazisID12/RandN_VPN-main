# RandN_VPN-main

## Установка и обновление

```sh
bash <(wget --no-hsts -qO- https://raw.githubusercontent.com/RazisID12/RandN_VPN-main/main/setup.sh)
```

## Настройка

### 1. Установить/удалить патч для обхода блокировки протокола OpenVPN

```sh
/opt/randn_vpn-main/patch-openvpn.sh
```

### 2. Включить/отключить OpenVPN DCO

```sh
/opt/randn_vpn-main/openvpn-dco.sh
```

### 3. Добавить/удалить клиента

```sh
/opt/randn_vpn-main/client.sh
```

### 4. Добавить/исключить свои сайты/IP

```sh
/opt/randn_vpn-main/doall.sh
```
