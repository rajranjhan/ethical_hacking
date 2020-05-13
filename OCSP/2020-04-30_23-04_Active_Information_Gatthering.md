## Active Information Gathering

* DNS
    - host [host.com]
        host -t mx [host.com]
        host -t text [host.com]
        for ip in $(cat list.txt); do host $ip.[host.com]; done
    
    