# notes-organizer

This script will generate an md file to be used as note for CTFs. It contains some of my notes in order to investigate each port/service.

The script is incomplete, this is only the first version.

# how to run

Inside a CTF box folder, run:

`❯ python ~/notes-organizer/main.py $ip`

If there is no nmap file at nmap folder, a message will be displayed:

```bash
[-] nmap files were not found. please run the commands below:
    -----------------------------------
-> aip TARGET_IP VHOST
-> sudo nmap -sS -p- $ip -vvv -n -Pn -T5 -oN nmap/ports.nmap
-> extractPorts nmap/ports.nmap
-> nmap -sC -sV -p$(cat nmap/ports.nmap | grep -oP '\d{2,5}/' | awk '{print $1}' FS="/" | xargs | tr ' ' ',') -n -Pn $ip -oA nmap/scan.nmap
    -----------------------------------
[+] run again
```

`aip` is a function I have on my zshrc file. It just export a environment variable named $ip. `extractPorts` is a function that parses the ports found on nmap scan and was modified from it's original created by S4vitar.

