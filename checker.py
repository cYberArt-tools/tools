# SSH, FTP and SMB anonymous misconfiguration scanner
# And
# Wordlist login Script


#------Imports------
from ftplib import FTP, error_perm
from smb.SMBConnection import SMBConnection
import paramiko
import socket
import ipaddress
import os
import warnings




 #-----Opening Wordlist path-----
def load_wordlist(wordlist_path):
    if not os.path.isfile(wordlist_path):
        print(f"[-] Wordlist not found: {wordlist_path}")
        return []
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


# ---------- Top 100 Common Username and Password Wordlists  ------------------
def top_100_ssh_usernames():
    return [
        "root", "admin", "user", "test", "guest", "ubuntu", "oracle", "ftp", "pi", "apache",
        "nginx", "mysql", "postgres", "ec2-user", "administrator", "developer", "dev", "sysadmin", "support",
        "staff", "student", "docker", "vagrant", "ansible", "jenkins", "node", "service", "monitor", "git", "gitlab",
        "cassandra", "hadoop", "spark", "tomcat", "wildfly", "jboss", "web", "backend", "frontend", "qa",
        "stage", "prod", "testuser", "user1", "admin1", "backup", "sync", "replica", "data", "engineer", "ops",
        "helpdesk", "network", "netadmin", "manager", "ceo", "cfo", "cio", "hr", "finance", "sales", "marketing",
        "bob", "alice", "charlie", "dave", "eve", "frank", "george", "harry", "ian", "jack", "jill", "joe", "john",
        "james", "mike", "nick", "nancy", "oliver", "paul", "quinn", "rachel", "steve", "susan", "tim", "victor",
        "wendy", "xavier", "yvonne", "zack", "tom", "lisa", "kevin", "emma", "sam", "leo", "dan"
    ]

def top_100_common_passwords():
    return [
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "abc123", "football", "monkey", "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "pussy", "superman", "1qaz2wsx",
        "7777777", "fuckyou", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer",
        "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine",
        "iloveyou", "fuckme", "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
        "klaster", "112233", "george", "asshole", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn",
        "555555", "11111111", "131313", "freedom", "777777", "pass", "fuck", "maggie", "159753", "aaaaaa", "ginger",
        "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley", "6969", "nicole", "chelsea", "biteme",
        "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "minecraft"
    ]


#-------FTP anonymous Login------
def ftp_anonymous_login(host, port=21):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=10)
        ftp.login()
        print(f"[+] Anonymous FTP login allowed on {host}:{port}")
        ftp.quit()
        return True
    except error_perm as e:
        print(f"[-] Anonymous FTP login is not allowed on this server, error {e}")
    except Exception as e:
        print(f"[-] An error occured while connecting to the server: {e}, possibly port closed")
    return False


#-------FTP single credential and wordlist login------
def ftp_login(host, port, usernames, passwords):
    for user in usernames:
        for password in passwords:
            try:
                ftp = FTP()
                ftp.connect(host, port, timeout=10)
                ftp.login(user, password)
                print(f"[+] FTP successful login with: {user}:{password}")
                ftp.quit()
                return True
            except error_perm:
                print(f"[-] FTP invalid credentials: {user}:{password}")
            except Exception as e:
                print(f"[-] An error occured while connecting to the server: {e}, possibly port closed")
                return False
    print("[-] Bruteforce FTP login failed for all combinations.")
    return False

# ----------- SMB anonymous login-------------
def smb_anonymous_login(host, port=139): #SMB anonymous login 
    try:
        conn = SMBConnection('', '', 'anonymous_client', host, use_ntlm_v2=True)
        if conn.connect(host, port, timeout=10):
            print(f"[+] Anonymous SMB login allowed on {host}:{port}")
            conn.close()
            return True
        else:
            print(f"[-] Anonymous SMB login not allowed on {host}:{port}")
    except Exception as e:
        print(f"[-] An error occured while connecting to the server:: {e}, possibly port closed")
    return False


#----------SMB single credential and wordlist login-------------
def smb_login(host, port, usernames, passwords): #SMB single and bruteforce login
    for user in usernames:
        for password in passwords:
            try:
                conn = SMBConnection(user, password, 'client', host, use_ntlm_v2=True)
                if conn.connect(host, port, timeout=10):
                    print(f"[+] SMB login success: {user}:{password}")
                    conn.close()
                    return True
                else:
                    print(f"[-] SMB invalid credentials: {user}:{password}")
            except Exception as e:
                print(f"[-] An error occured while connecting to the server: {e}, possibly port closed")
                return False
    print("[-] No Credentials found.")
    return False

# ------------ SSH single credential and wordlist login ---------------
def ssh_login(host, port, usernames, passwords):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user in usernames:
        for password in passwords:
            try:
                ssh.connect(host, port=port, username=user, password=password, timeout=5)
                print(f"[+] SSH login success: {user}:{password}")
                ssh.close()
                return True
            except paramiko.AuthenticationException:
                print(f"[-] SSH invalid credentials: {user}:{password}")
            except Exception as e:
                print(f"[-] An error occured while SSH to the server error: {e}, possibly port closed")
                return False
    print("[-] No Credentials found.")
    return False

#--------SSH anonymous login error---------
def ssh_anonymous_login():
    print("[-] SSH do not support anonymous login like FTP and SMB.")
    return False

# ------------------ Main function------------------
if __name__ == "__main__":
    target_hostname = input("Enter target host or CIDR (e.g. 192.168.1.0/24 or 10.0.0.5): ").strip()
    ip_array = []
    
    #------CIDR validation-----
    try:
        if '/' in target_hostname:
            network = ipaddress.ip_network(target_hostname, strict=False)
            ip_array = [str(ip) for ip in network.hosts()]
            print(f"[*] Expanding network: {len(ip_array)} hosts found.")
        else:
            ip_array = [target_hostname]
    except ValueError as e:
        print(f"[-] Invalid IP or CIDR format: {e}")
        exit(1)

    #--------User protocol selection and login method-------
    protocol = input("Which protocol to check? (ftp/smb/ssh/all): ").strip().lower()
    mode = input("Use anonymous login, wordlist or single word? (anon/wordlist/single): ").strip().lower()

    usernames = []
    passwords = []

    if mode == 'wordlist':
        user_file = input("Path to username wordlist (press Enter to use top 100 common usernames: ").strip()
        pass_file = input("Path to password wordlist (press Enter to use top 100 common passwords: ").strip()

        if user_file:
            usernames = load_wordlist(user_file)
        if pass_file:
            passwords = load_wordlist(pass_file)

    elif mode == 'single':  
            single_usernames = input("Insert single username: ").strip()
            single_passwords = input("Insert single password: ").strip()
            usernames = [single_usernames]
            passwords = [single_passwords]

    #------- Method and protocol checks------
    def run_checks():
        if protocol in ["ftp", "all"]:
            print("\n--- Checking FTP ---")
            if mode == 'anon':
                ftp_anonymous_login(target_hostname)
            else:
                if not usernames:
                    print("[*] No username list provided. Using top 100 usernames.")
                    usernames.extend(top_100_ssh_usernames())
                if not passwords:
                    print("[*] No password list provided. Using top 100 passwords.")
                    passwords.extend(top_100_common_passwords())
                ftp_login(target_hostname, 21, usernames, passwords)

        if protocol in ["smb", "all"]:
            print("\n--- Checking SMB ---")
            if mode == 'anon':
                smb_anonymous_login(target_hostname)
            else:
                if not usernames:
                    print("[*] No username list provided. Using top 100 usernames.")
                    usernames.extend(top_100_ssh_usernames())
                if not passwords:
                    print("[*] No password list provided. Using top 100 passwords.")
                    passwords.extend(top_100_common_passwords())
                smb_login(target_hostname, 139, usernames, passwords)

        if protocol in ["ssh", "all"]:
            print("\n--- Checking SSH ---")
            if mode == 'anon':
                ssh_anonymous_login()
            else:
                if not usernames:
                    print("[*] No username list provided. Using top 100 usernames.")
                    usernames.extend(top_100_ssh_usernames())
                if not passwords:
                    print("[*] No password list provided. Using top 100 passwords.")
                    passwords.extend(top_100_common_passwords())
                ssh_login(target_hostname, 22, usernames, passwords)
    #-----Host IP Display------
    for target_hostname in ip_array:
        print(f"\n====== Scanning {target_hostname} ======")
        run_checks()