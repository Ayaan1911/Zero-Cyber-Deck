# Learning resources (offline index)

Links need internet; this page works offline as a reading list. Practice only on systems you own or on platforms built for it.

## Practice platforms (legal by design)
- OverTheWire wargames: https://overthewire.org/wargames/ (Linux, shell basics -> exploitation)
- picoCTF: https://picoctf.org/ (beginner-friendly CTF, year-round practice gym)
- Hack The Box / TryHackMe: https://www.hackthebox.com/ , https://tryhackme.com/ (guided labs; free tiers vary)
- PortSwigger Web Security Academy: https://portswigger.net/web-security (free web-vulnerability labs; pairs with Burp Suite)
- CTFtime: https://ctftime.org/ (event calendar and writeups)
- pwn.college: https://pwn.college/ ; Exploit Education: https://exploit.education/ (binary exploitation, local VMs)
- OWASP Top 10 and WebGoat/Juice Shop: https://owasp.org/ (deliberately vulnerable apps to run locally)

## Reference
- Nmap book (free online): https://nmap.org/book/
- Kali documentation: https://www.kali.org/docs/
- Metasploit Unleashed (lab walkthroughs): https://www.offsec.com/metasploit-unleashed/
- CyberChef (encoding/crypto swiss-army knife; can be downloaded and run offline): https://gchq.github.io/CyberChef/
- CTF 101: https://ctf101.org/

## Build your own lab (recommended before touching Metasploit)
1. Host-only network in VirtualBox/VMware (e.g. 192.168.56.0/24); no bridge to your real LAN.
2. Targets: Metasploitable 2/3, DVWA, Juice Shop, or an intentionally vulnerable VM from VulnHub.
3. Put ONLY that range in `config/scope.txt`. The deck refuses everything else.
4. Snapshot VMs before each exercise; keep notes with the deck's "Create a CTF/lab note" item.

## Habits
Write down scope and permission first, keep notes without real credentials, hash what you collect, and report findings responsibly.
