Asymmetric Hello
================
Asymmetric Hello achieves censorship circumvention of the Web via asymmetric rerouting of TLS Client Hello. Unlike a VPN, Asymmetric Hello preserves your Internet Protocol address.

This is highly experimental software. Currently Asymmetric Hello can from behind the Great Firewall of China unblock Facebook, Google, Wikipedia, Spotify, and Youtube.

How it works
------------
Because of extensive use of cryptography and shared hosting on the modern Internet, often the only source of information censors may act on to block websites is the Transport Layer Security (TLS) Client Hello --- an unencrypted declaration by your browser of the website it's trying to visit sent to the Internet whenever your browser is establishing a new connection. Asymmetric Hello denies censors access to this information. 

Asymmetric Hello captures packets on TCP port 443 containing TLS Client Hello, reroutes them out of your censor's network in a encrypted tunnel, then returns them to the Internet using Internet Protocol address spoofing. See schematic below:

![How Asymmetric Hello basically works](https://share.konaa.ca/Asymmetric%20Hello.svg)

Asymmetric Hello is not a substitute for TLS Encrypted Client Hello. 

Setup
-----
### Building
1.	Install:
	-	Go with CGo
	-	libnftables and libnetfilter_queue development files
2. Run `CGO_ENABLED=1 go build -o=asymhello github.com/KonaArctic/Asymmetric-Hello/main`

### Injection Server
Asymmetric Hello requires an injection server. Your server must tolerate Internet Protocol (IP) address spoofing, must be outside of your censor's network, and should be as topologically close to you as feasible. 

1.	Generate a secret key [SECRET], compute its SHA-256 digest [DIGEST], and determine your server's IP address(es) [SERVER] 
2.	Obtain a TLS certificate. Let's Encrypt is sufficient
3.  Run `ip6tables --table=filter --append=OUTPUT --source=[SERVER] --jump=ACCEPT && ip6tables --table=filter --append=OUTPUT --match=tcp --protocol=tcp --destination-port=443 --jump=ACCEPT && ip6tables --table=filter --append=OUTPUT --jump=DROP` 
4.	Run `KONA_TLS_CERTIFICATE_WITH_PRIVATE_KEY=$(cat {fullchain,privkey}.pem) $(pwd)/asymhello server --delays=1ns --listen=\[::\]:443 --resolv=\[2001:4860:4860::8888\]:53 --tokens=[DIGEST]`

### Client
Your Internet service must be dualstack.

1.	Install:
    -	Unix utilities
	-	bash, curl, grepcidr, named-checkzone, and nmap
2.	Flush or disable any firewalls, including any firewall on your Internet router
3.	Run `ip6tables --table=filter --append=INPUT --match=tcp --protocol=tcp --source-port=443 --tcp-flags RST RST --jump=DROP`
4.	Run `bash resolve/prepare.sh [RESOLV]` where [RESOLV] is an uncensored recursive DNS resolver.
    -	Try `ssh -L[RESOLV]:\[2001:4860:4860::8888\]:53 [SERVER]`
5.	Run `$(pwd)/asymhello client --anycast=anycatch-v6-prefixes.txt --resolv=resolve/resolve.sh --server=https://:[SECRET]@[SERVER]/`
6.	Enjoy :)

Caveats
-------
Known bugs, problems, and limitations:

+ Slow and buggy, expect random segfaults and crashes
+ Does not work with some websites
+ Does not support other encrypted protocols
+ Lacks IPv4 support
    - Unfortunately carrier grade/symmetric NAT, the most common types of NAT today, mangles packets in difficult-to-predict ways  

License
-------
Copyright © 2026 Kona Arctic, all rights reserved. ABSOLUTELY NO WARRANTY! You may use this software for personal non-commercial evaluation purposes only. 