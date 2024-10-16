#!/usr/bin/env python3

import os
import subprocess
import pwd
import grp
import re
import sys
import hashlib

# Function to check if the script is run as root
def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

# Function to check for weak passwords in /etc/shadow
def check_weak_passwords():
    print("Checking for weak passwords...")
    weak_password_users = []
    try:
        with open('/etc/shadow', 'r') as shadow_file:
            for line in shadow_file:
                parts = line.strip().split(':')
                if len(parts) > 1:
                    username = parts[0]
                    password_hash = parts[1]
                    # Skip locked accounts or accounts without passwords
                    
            print("Users with passwords:")
            for user, pwd_hash in weak_password_users:
                print(f"- Username: {user}, Password Hash: {pwd_hash}")
       
    except PermissionError:
        print("Permission denied: Unable to read /etc/shadow. Run the script as root.")
    except Exception as e:
        print(f"Error checking weak passwords: {e}")


# Function to search for unauthorized media files
def check_media_files():
    print("Searching for unauthorized media files...")
    media_extensions = ['*.mp3', '*.mp4', '*.avi', '*.mkv', '*.wav', '*.flac']
    unauthorized_files = []
    for ext in media_extensions:
        command = ['find', '/', '-type', 'f', '-name', ext, '-not', '-path', '/proc/*', '-not', '-path', '/sys/*', '-not', '-path', '/run/*', '-not', '/opt/*', '-path', '/dev/*', '-not', '-path', '/var/lib/*', '-not', '-path', '/var/run/*']
        try:
            result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
            files = result.decode().split('\n')
            unauthorized_files.extend([f for f in files if f])
        except subprocess.CalledProcessError:
            continue
    if unauthorized_files:
        print("Unauthorized media files found:")
        for file in unauthorized_files:
            print(file)
    else:
        print("No unauthorized media files found.")

# Function to search for installed hacking tools
def check_hacking_tools():
    print("Checking for unauthorized hacking tools...")
    hacking_tools = [
        'nmap', 'hydra', 'netcat', 'john', 'sqlmap', 'aircrack-ng', 'metasploit',
        'wireshark', 'nikto', 'burpsuite', 'ettercap', 'kismet', 'responder', 
        'reaver', 'medusa', 'hashcat', 'msfconsole', 'beef', 'angryip', 'snort', 
        'tcpdump', 'tshark', 'openvas', 'owasp-zap', 'w3af', 'hping3', 'zmap', 
        'amass', 'fierce', 'arpspoof', 'macchanger', 'dnsenum', 'dnsmap', 
        'yersinia', 'sqlninja', 'exploitdb', 'setoolkit', 'maltego', 'shellshock', 
        'cewl', 'wpscan', 'dirbuster', 'powersploit', 'empire', 'bloodhound', 
        'crackmapexec', 'impacket', 'kerbrute', 'pupy', 'cobaltstrike', 
        'veil', 'faraday', 'binwalk', 'firmware-mod-kit', 'gobuster', 
        'bettercap', 'proxychains', 'socat', 'chaosreader', 'dnsrecon', 
        'enum4linux', 'msfvenom', 'evil-winrm', 'patator', 'brutespray',
        'nbtscan', 'sslscan', 'masscan', 'searchsploit', 'aquatone',
        'sublist3r', 'seclists', 'fping', 'theharvester', 'nikto', 'netdiscover',
        'sparta', 'slowloris', 'cadaver', 'sslyze', 'dnschef', 'skipfish', 'xsser']
    installed_tools = []
    for tool in hacking_tools:
        command = ['which', tool]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            installed_tools.append(tool)
    if installed_tools:
        print("Unauthorized hacking tools installed: ", installed_tools)
    else:
        print("No unauthorized hacking tools found.")

# Function to check if IPv6 is enabled
def check_ipv6():
    print("Checking if IPv6 is enabled...")
    ipv6_enabled = False
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'r') as ipv6_file:
            status = ipv6_file.read().strip()
            if status == '0':
                ipv6_enabled = True
    except FileNotFoundError:
        ipv6_enabled = True  # If the file doesn't exist, IPv6 may be enabled
    if ipv6_enabled:
        print("IPv6 is enabled. It should be disabled.")
    else:
        print("IPv6 is disabled.")

# Function to check SSH configuration
def check_ssh_config():
    print("Checking SSH configuration...")
    try:
        with open('/etc/ssh/sshd_config', 'r') as ssh_config:
            config = ssh_config.read()
            if 'PermitRootLogin no' not in config:
                print("Root login over SSH is permitted. It should be disabled.")
            else:
                print("Root login over SSH is disabled.")
            if 'Protocol 2' not in config:
                print("SSH Protocol 2 is not enforced. It should be set.")
            else:
                print("SSH Protocol 2 is enforced.")
            # Check for allowed users/groups
            if 'AllowUsers' not in config and 'AllowGroups' not in config:
                print("No specific users or groups are allowed to SSH. Consider restricting access.")
            else:
                print("SSH access is restricted to specific users/groups.")
    except Exception as e:
        print(f"Error checking SSH configuration: {e}")

# Function to check Samba configuration
def check_samba_config():
    print("Checking Samba configuration...")
    smb_conf = '/etc/samba/smb.conf'
    if os.path.exists(smb_conf):
        try:
            with open(smb_conf, 'r') as smb_file:
                config = smb_file.read()
                if 'map to guest = never' not in config:
                    print("Guest access is allowed in Samba. It should be disabled.")
                else:
                    print("Guest access in Samba is disabled.")
                # Check for public shares
                public_shares = re.findall(r'\[([^\]]+)\]\s+public\s*=\s*yes', config, re.IGNORECASE)
                if public_shares:
                    print("Public shares found in Samba:")
                    for share in public_shares:
                        print(f"- {share}")
                else:
                    print("No public shares found in Samba.")
        except Exception as e:
            print(f"Error checking Samba configuration: {e}")
    else:
        print("Samba is not installed.")

# Function to check for outdated packages
def check_outdated_packages():
    print("Checking for outdated packages...")
    try:
        command = ['apt', 'list', '--upgradable']
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        packages = result.decode().split('\n')[1:-1]
        if packages:
            print("Outdated packages found:")
            for pkg in packages:
                print(pkg)
        else:
            print("All packages are up to date.")
    except Exception as e:
        print(f"Error checking for outdated packages: {e}")

# Function to check firewall status
def check_firewall():
    print("Checking firewall status...")
    try:
        command = ['ufw', 'status']
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        status = result.decode().strip()
        if 'Status: inactive' in status:
            print("UFW firewall is inactive. It should be enabled and configured.")
        else:
            print("UFW firewall is active.")
    except Exception as e:
        print(f"Error checking firewall status: {e}")

# Function to check for unnecessary services
def check_services():
    print("Checking for unnecessary or insecure services...")
    # List of services that should not be running
    unnecessary_services = [
        'telnet', 'ftp', 'rlogin', 'rexec', 'rsh', 'nfs', 'rpcbind', 
        'tftp', 'chargen', 'daytime', 'discard', 'finger', 'ntalk',
        'talk', 'bootp', 'cups', 'lp', 'nntp', 'pop3', 'imap', 'snmp', 
        'samba', 'xinetd', 'vsftpd', 'qotd', 'identd', 'portmap', 'rsync', 
        'nmbd', 'winbind', 'nis', 'uucp', 'sendmail', 'postfix', 'exim', 
        'telnetd', 'wu-ftpd', 'proftpd', 'dovecot', 'dbus', 'x11-common'
    ]   
    running_services = []
    for service in unnecessary_services:
        command = ['systemctl', 'is-active', service]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            running_services.append(service)
    if running_services:
        print("Unnecessary or insecure services are running: ", running_services)
    else:
        print("No unnecessary or insecure services are running.")

# Function to check for users with UID 0 besides root
def check_uid_zero_users():
    print("Checking for users with UID 0 besides root...")
    uid_zero_users = []
    for user in pwd.getpwall():
        if user.pw_uid == 0 and user.pw_name != 'root':
            uid_zero_users.append(user.pw_name)
    if uid_zero_users:
        print("Users with UID 0 found: ", uid_zero_users)
    else:
        print("No users with UID 0 besides root.")

# Function to check for world-writable files
def check_world_writable_files():
    print("Checking for world-writable files...")
    command = ['find', '/', '-xdev', '-type', 'f', '-perm', '-0002', '-not', '-path', '/proc/*', '-not', '-path', '/sys/*', '-not', '-path', '/run/*', '-not', '-path', '/dev/*']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        files = result.decode().split('\n')
        world_writable_files = [f for f in files if f]
        if world_writable_files:
            print("World-writable files found:")
            for file in world_writable_files:
                print(file)
        else:
            print("No world-writable files found.")
    except Exception as e:
        print(f"Error checking for world-writable files: {e}")

# Function to check for empty password fields in /etc/passwd
def check_empty_passwords():
    print("Checking for users with empty passwords...")
    empty_password_users = []
    try:
        with open('/etc/passwd', 'r') as passwd_file:
            for line in passwd_file:
                parts = line.strip().split(':')
                if len(parts) > 1:
                    username = parts[0]
                    password_field = parts[1]
                    if password_field == '':
                        empty_password_users.append(username)
        if empty_password_users:
            print("Users with empty password fields: ", empty_password_users)
        else:
            print("No users with empty password fields found.")
    except Exception as e:
        print(f"Error checking empty passwords: {e}")

# Function to check password policy in /etc/login.defs
def check_password_policy():
    print("Checking password policy...")
    try:
        with open('/etc/login.defs', 'r') as login_defs:
            content = login_defs.read()
            pass_min_len = re.search(r'^\s*PASS_MIN_LEN\s+(\d+)', content, re.MULTILINE)
            if pass_min_len:
                min_len = int(pass_min_len.group(1))
                if min_len < 12:
                    print(f"Minimum password length is set to {min_len}. It should be at least 12.")
                else:
                    print(f"Minimum password length is set to {min_len}.")
            else:
                print("PASS_MIN_LEN is not set.")
    except Exception as e:
        print(f"Error checking password policy: {e}")

# Function to check if root's home directory is secure
def check_root_home_permissions():
    print("Checking root's home directory permissions...")
    try:
        root_stat = os.stat('/root')
        permissions = oct(root_stat.st_mode & 0o777)
        if permissions != '0o700':
            print(f"Root's home directory permissions are {permissions}. They should be 700.")
        else:
            print("Root's home directory permissions are secure.")
    except Exception as e:
        print(f"Error checking root's home permissions: {e}")

# Function to check for root cron jobs
def check_root_cron():
    print("Checking for root cron jobs...")
    cron_jobs = []
    cron_files = ['/etc/crontab', '/var/spool/cron/root']
    for cron_file in cron_files:
        if os.path.exists(cron_file):
            with open(cron_file, 'r') as file:
                jobs = file.readlines()
                cron_jobs.extend([job.strip() for job in jobs if job.strip() and not job.startswith('#')])
    if cron_jobs:
        print("Root cron jobs found:")
        for job in cron_jobs:
            print(job)
    else:
        print("No root cron jobs found.")

# Function to check for SUID/SGID files
def check_suid_sgid_files():
    print("Checking for SUID/SGID files...")
    command = ['find', '/', '-xdev', '-type', 'f', '-perm', '/6000', '-not', '-path', '/proc/*', '-not', '-path', '/sys/*', '-not', '-path', '/run/*', '-not', '-path', '/dev/*']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        files = result.decode().split('\n')
        suid_sgid_files = [f for f in files if f]
        if suid_sgid_files:
            print("SUID/SGID files found:")
            for file in suid_sgid_files:
                print(file)
        else:
            print("No SUID/SGID files found.")
    except Exception as e:
        print(f"Error checking SUID/SGID files: {e}")

# Function to check for users with shell access
def check_shell_access_users():
    print("Checking for users with shell access...")
    shell_users = []
    for user in pwd.getpwall():
        if user.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
            shell_users.append(user.pw_name)
    if shell_users:
        print("Users with shell access: ", shell_users)
    else:
        print("No users with shell access found.")

# Function to check for duplicate UIDs and GIDs
def check_duplicate_ids():
    print("Checking for duplicate UIDs and GIDs...")
    uids = {}
    gids = {}
    for user in pwd.getpwall():
        uids.setdefault(user.pw_uid, []).append(user.pw_name)
    for group in grp.getgrall():
        gids.setdefault(group.gr_gid, []).append(group.gr_name)
    duplicate_uids = {uid: names for uid, names in uids.items() if len(names) > 1}
    duplicate_gids = {gid: names for gid, names in gids.items() if len(names) > 1}
    if duplicate_uids:
        print("Duplicate UIDs found:")
        for uid, names in duplicate_uids.items():
            print(f"UID {uid}: {', '.join(names)}")
    else:
        print("No duplicate UIDs found.")
    if duplicate_gids:
        print("Duplicate GIDs found:")
        for gid, names in duplicate_gids.items():
            print(f"GID {gid}: {', '.join(names)}")
    else:
        print("No duplicate GIDs found.")

# Function to check for password hashes in /etc/passwd
def check_passwd_hashes():
    print("Checking for password hashes in /etc/passwd...")
    hashes_found = False
    try:
        with open('/etc/passwd', 'r') as passwd_file:
            for line in passwd_file:
                parts = line.strip().split(':')
                if len(parts) > 1:
                    password_field = parts[1]
                    if password_field not in ['x', '*', '!']:
                        hashes_found = True
                        print(f"Password hash found for user {parts[0]} in /etc/passwd.")
        if not hashes_found:
            print("No password hashes found in /etc/passwd.")
    except Exception as e:
        print(f"Error checking /etc/passwd: {e}")

def check_sudoers():
    print("Checking sudoers file for unauthorized users...")
    authorized_users = ['root', 'admin']  # Replace with actual authorized users
    sudoers_file = '/etc/sudoers'
    sudoers_users = []
    try:
        with open(sudoers_file, 'r') as file:
            for line in file:
                if re.match(r'^[^#].*ALL\s*=\s*\(ALL\)', line):
                    user = line.split()[0]
                    if user not in authorized_users:
                        sudoers_users.append(user)
        if sudoers_users:
            print("Unauthorized users with sudo access: ", sudoers_users)
        else:
            print("No unauthorized sudoers found.")
    except Exception as e:
        print(f"Error checking sudoers file: {e}")

# Function to check for open ports and unnecessary services
def check_open_ports():
    print("Checking for open ports and unnecessary services...")
    necessary_ports = [22, 80, 443, 139, 445]  # Modify based on required services
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        lines = result.decode().split('\n')
        open_ports = []
        for line in lines:
            match = re.search(r'LISTEN.*:(\d+)', line)
            if match:
                port = int(match.group(1))
                if port not in necessary_ports:
                    open_ports.append(port)
        if open_ports:
            print("Unnecessary open ports found: ", open_ports)
        else:
            print("No unnecessary open ports found.")
    except Exception as e:
        print(f"Error checking open ports: {e}")

# Function to check for incorrect file permissions on critical files
def check_critical_file_permissions():
    print("Checking permissions of critical system files...")
    critical_files = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow']
    for file in critical_files:
        try:
            stat_info = os.stat(file)
            permissions = oct(stat_info.st_mode & 0o777)
            if file == '/etc/shadow' and permissions != '0o600':
                print(f"Incorrect permissions for {file}: {permissions}. Should be 600.")
            elif file != '/etc/shadow' and permissions != '0o644':
                print(f"Incorrect permissions for {file}: {permissions}. Should be 644.")
            else:
                print(f"Permissions for {file} are correct.")
        except Exception as e:
            print(f"Error checking permissions for {file}: {e}")

# Function to check for root-owned files in user directories
def check_root_owned_files_in_home():
    print("Checking for root-owned files in user home directories...")
    for user in pwd.getpwall():
        home_dir = user.pw_dir
        if os.path.isdir(home_dir) and user.pw_name not in ['root', 'nobody']:
            command = ['find', home_dir, '-user', 'root', '-type', 'f']
            try:
                result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
                files = result.decode().split('\n')
                root_files = [f for f in files if f]
                if root_files:
                    print(f"Root-owned files found in {user.pw_name}'s home directory:")
                    for file in root_files:
                        print(file)
            except Exception as e:
                continue

# Function to check for world-writable directories
def check_world_writable_directories():
    print("Checking for world-writable directories...")
    command = ['find', '/', '-xdev', '-type', 'd', '-perm', '-0002', '-not', '-path', '/proc/*', '-not', '-path', '/sys/*', '-not', '-path', '/run/*', '-not', '-path', '/dev/*']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        directories = result.decode().split('\n')
        world_writable_dirs = [d for d in directories if d]
        if world_writable_dirs:
            print("World-writable directories found:")
            for directory in world_writable_dirs:
                print(directory)
        else:
            print("No world-writable directories found.")
    except Exception as e:
        print(f"Error checking world-writable directories: {e}")

# Function to check for services running as root unnecessarily
def check_services_running_as_root():
    print("Checking for services running as root unnecessarily...")
    try:
        result = subprocess.check_output(['ps', '-eo', 'user,comm'], stderr=subprocess.DEVNULL)
        processes = result.decode().split('\n')
        root_services = []
        for process in processes:
            parts = process.strip().split()
            if len(parts) == 2 and parts[0] == 'root':
                service = parts[1]
                if service not in ['sshd', 'systemd', 'kthreadd']:  # Add necessary root services here
                    root_services.append(service)
        if root_services:
            print("Services running as root that may not need to:")
            for service in set(root_services):
                print(service)
        else:
            print("No unnecessary services running as root found.")
    except Exception as e:
        print(f"Error checking services running as root: {e}")

# Function to check for weak SSH keys
def check_weak_ssh_keys():
    print("Checking for weak SSH keys...")
    ssh_dir = '/etc/ssh'
    key_files = ['ssh_host_dsa_key', 'ssh_host_ecdsa_key', 'ssh_host_ed25519_key', 'ssh_host_rsa_key']
    weak_keys = []
    for key_file in key_files:
        key_path = os.path.join(ssh_dir, key_file)
        if os.path.exists(key_path):
            try:
                result = subprocess.check_output(['ssh-keygen', '-lf', key_path])
                key_info = result.decode().strip()
                if '1024' in key_info:
                    weak_keys.append(key_file)
            except Exception as e:
                continue
    if weak_keys:
        print("Weak SSH keys found:")
        for key in weak_keys:
            print(key)
    else:
        print("No weak SSH keys found.")

# Function to check for unencrypted FTP service
def check_ftp_service():
    print("Checking for unencrypted FTP service...")
    try:
        result = subprocess.check_output(['systemctl', 'is-active', 'vsftpd'], stderr=subprocess.DEVNULL)
        if result.decode().strip() == 'active':
            print("Unencrypted FTP service is running. It should be disabled or secured.")
        else:
            print("FTP service is not running.")
    except Exception as e:
        print("FTP service is not installed or an error occurred.")

# Function to check for anonymous FTP access
def check_anonymous_ftp():
    print("Checking for anonymous FTP access...")
    vsftpd_conf = '/etc/vsftpd.conf'
    if os.path.exists(vsftpd_conf):
        try:
            with open(vsftpd_conf, 'r') as file:
                config = file.read()
                if 'anonymous_enable=YES' in config:
                    print("Anonymous FTP access is enabled. It should be disabled.")
                else:
                    print("Anonymous FTP access is disabled.")
        except Exception as e:
            print(f"Error checking FTP configuration: {e}")
    else:
        print("vsftpd configuration file not found.")

# Function to check for core dumps enabled
def check_core_dumps():
    print("Checking if core dumps are enabled...")
    try:
        with open('/proc/sys/kernel/core_pattern', 'r') as file:
            core_pattern = file.read().strip()
            if core_pattern != '|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %e':
                print("Core dumps are enabled. They should be restricted or disabled.")
            else:
                print("Core dumps are properly handled.")
    except Exception as e:
        print(f"Error checking core dump settings: {e}")

# Function to check for misconfigured firewall rules
def check_firewall_rules():
    print("Checking firewall rules for misconfigurations...")
    try:
        result = subprocess.check_output(['iptables', '-L'], stderr=subprocess.DEVNULL)
        rules = result.decode()
        if 'ACCEPT' in rules and '0.0.0.0/0' in rules:
            print("Firewall has ACCEPT rules for all traffic. This may be insecure.")
        else:
            print("Firewall rules are configured.")
    except Exception as e:
        print("Error checking firewall rules or iptables is not installed.")

# Function to check for improper cron job permissions
def check_cron_permissions():
    print("Checking cron job permissions...")
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly']
    for directory in cron_dirs:
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    stat_info = os.stat(filepath)
                    permissions = oct(stat_info.st_mode & 0o777)
                    if permissions != '0o600' and permissions != '0o700':
                        print(f"Incorrect permissions for {filepath}: {permissions}. Should be 600 or 700.")
    print("Cron job permissions check completed.")

# Function to check for improper PATH environment variable settings
def check_path_variable():
    print("Checking PATH environment variable for insecure entries...")
    path = os.environ.get('PATH', '')
    insecure_entries = [entry for entry in path.split(':') if entry == '' or entry == '.' or not os.path.exists(entry)]
    if insecure_entries:
        print("Insecure PATH entries found: ", insecure_entries)
    else:
        print("PATH environment variable is secure.")

# Function to check for unrestricted SNMP access
def check_snmp_settings():
    print("Checking SNMP settings for security...")
    snmp_conf = '/etc/snmp/snmpd.conf'
    if os.path.exists(snmp_conf):
        try:
            with open(snmp_conf, 'r') as file:
                config = file.read()
                if 'public' in config:
                    print("SNMP community string 'public' is used. It should be changed.")
                else:
                    print("SNMP community string is not 'public'.")
        except Exception as e:
            print(f"Error checking SNMP configuration: {e}")
    else:
        print("SNMP is not installed or snmpd.conf not found.")

# Function to check for unnecessary kernel modules
def check_kernel_modules():
    print("Checking for unnecessary kernel modules...")
    try:
        result = subprocess.check_output(['lsmod'], stderr=subprocess.DEVNULL)
        modules = result.decode().split('\n')
        unnecessary_modules = ['cramfs', 'freevxfs', 'hfs', 'hfsplus', 'jffs2', 'squashfs', 'udf']
        loaded_modules = [line.split()[0] for line in modules if line]
        found_modules = [module for module in unnecessary_modules if module in loaded_modules]
        if found_modules:
            print("Unnecessary kernel modules loaded: ", found_modules)
        else:
            print("No unnecessary kernel modules loaded.")
    except Exception as e:
        print(f"Error checking kernel modules: {e}")

# Function to check for misconfigured or missing logs
def check_logging():
    print("Checking for misconfigured or missing logs...")
    log_files = ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages']
    for log_file in log_files:
        if not os.path.exists(log_file):
            print(f"Log file {log_file} is missing.")
        else:
            print(f"Log file {log_file} exists.")
    print("Logging configuration check completed.")

# Function to check for empty groups
def check_empty_groups():
    print("Checking for empty groups...")
    empty_groups = []
    for group in grp.getgrall():
        if not group.gr_mem:
            empty_groups.append(group.gr_name)
    if empty_groups:
        print("Empty groups found: ", empty_groups)
    else:
        print("No empty groups found.")

# Function to check for incorrect NTP configuration
def check_ntp_config():
    print("Checking NTP configuration...")
    ntp_conf_files = ['/etc/ntp.conf', '/etc/chrony/chrony.conf']
    ntp_configured = False
    for conf_file in ntp_conf_files:
        if os.path.exists(conf_file):
            ntp_configured = True
            print(f"NTP is configured using {conf_file}.")
            break
    if not ntp_configured:
        print("NTP is not configured.")

# Function to check for unrestricted mail relaying
def check_mail_relay():
    print("Checking for unrestricted mail relaying...")
    postfix_conf = '/etc/postfix/main.cf'
    if os.path.exists(postfix_conf):
        try:
            with open(postfix_conf, 'r') as file:
                config = file.read()
                if 'smtpd_recipient_restrictions' not in config or 'permit_mynetworks' in config:
                    print("Mail relaying may be unrestricted. Check Postfix configuration.")
                else:
                    print("Mail relaying restrictions are configured.")
        except Exception as e:
            print(f"Error checking Postfix configuration: {e}")
    else:
        print("Postfix is not installed or main.cf not found.")

# Function to check for unnecessary X11 forwarding
def check_x11_forwarding():
    print("Checking for unnecessary X11 forwarding in SSH...")
    try:
        with open('/etc/ssh/sshd_config', 'r') as ssh_config:
            config = ssh_config.read()
            if 'X11Forwarding yes' in config:
                print("X11 forwarding is enabled in SSH. It should be disabled if not needed.")
            else:
                print("X11 forwarding is disabled.")
    except Exception as e:
        print(f"Error checking SSH X11 forwarding configuration: {e}")

# Function to check for presence of .rhosts files
def check_rhosts_files():
    print("Checking for .rhosts files in user directories...")
    for user in pwd.getpwall():
        home_dir = user.pw_dir
        rhosts_file = os.path.join(home_dir, '.rhosts')
        if os.path.exists(rhosts_file):
            print(f".rhosts file found in {user.pw_name}'s home directory.")
    print("Check for .rhosts files completed.")

# Function to check for duplicate host keys in SSH
def check_ssh_host_keys():
    print("Checking for duplicate SSH host keys...")
    host_keys = ['/etc/ssh/ssh_host_rsa_key.pub', '/etc/ssh/ssh_host_dsa_key.pub']
    keys_hashes = []
    for key_file in host_keys:
        if os.path.exists(key_file):
            with open(key_file, 'rb') as file:
                key_data = file.read()
                key_hash = hashlib.sha256(key_data).hexdigest()
                if key_hash in keys_hashes:
                    print(f"Duplicate SSH host key detected: {key_file}")
                else:
                    keys_hashes.append(key_hash)
    print("SSH host keys check completed.")

# Function to check for unowned files and directories
def check_unowned_files():
    print("Checking for unowned files and directories...")
    command = ['find', '/', '-xdev', '-nouser', '-o', '-nogroup', '-not', '-path', '/proc/*', '-not', '-path', '/sys/*', '-not', '-path', '/run/*', '-not', '-path', '/dev/*']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        files = result.decode().split('\n')
        unowned_files = [f for f in files if f]
        if unowned_files:
            print("Unowned files and directories found:")
            for file in unowned_files:
                print(file)
        else:
            print("No unowned files or directories found.")
    except Exception as e:
        print(f"Error checking for unowned files: {e}")

# Function to check for processes listening on wildcard addresses
def check_listening_processes():
    print("Checking for processes listening on wildcard addresses...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        lines = result.decode().split('\n')
        insecure_listeners = []
        for line in lines:
            if '0.0.0.0' in line or ':::' in line:
                insecure_listeners.append(line.strip())
        if insecure_listeners:
            print("Processes listening on wildcard addresses:")
            for listener in insecure_listeners:
                print(listener)
        else:
            print("No processes listening on wildcard addresses found.")
    except Exception as e:
        print(f"Error checking listening processes: {e}")

# Function to check for unnecessary packages installed
def check_unnecessary_packages():
    print("Checking for unnecessary packages installed...")
    unnecessary_packages = ['telnet', 'rsh-client', 'rsh-server', 'talk', 'talkd', 'xinetd', 'ypbind', 'ypserv', 'tftp', 'tftpd', 'rsh', 'rcp']
    installed_packages = []
    for package in unnecessary_packages:
        result = subprocess.run(['dpkg', '-l', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            installed_packages.append(package)
    if installed_packages:
        print("Unnecessary packages installed: ", installed_packages)
    else:
        print("No unnecessary packages installed.")

# Function to check for default accounts and passwords
def check_default_accounts():
    print("Checking for default accounts and passwords...")
    default_accounts = ['guest', 'user', 'test']
    accounts_found = []
    for user in pwd.getpwall():
        if user.pw_name in default_accounts:
            accounts_found.append(user.pw_name)
    if accounts_found:
        print("Default accounts found: ", accounts_found)
    else:
        print("No default accounts found.")

# Function to check for presence of backup files
def check_backup_files():
    print("Checking for presence of backup files...")
    command = ['find', '/', '-xdev', '-type', 'f', '-name', '*~', '-o', '-name', '*.bak', '-o', '-name', '*.old', '-o', '-name', '*.orig', '-not', '-path', '/proc/*', '-not', '-path', '/sys/*', '-not', '-path', '/run/*', '-not', '-path', '/dev/*']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        files = result.decode().split('\n')
        backup_files = [f for f in files if f]
        if backup_files:
            print("Backup files found:")
            for file in backup_files:
                print(file)
        else:
            print("No backup files found.")
    except Exception as e:
        print(f"Error checking for backup files: {e}")

# Function to check for old kernel versions
def check_old_kernels():
    print("Checking for old kernel versions installed...")
    try:
        result = subprocess.check_output(['dpkg', '--list', 'linux-image*'], stderr=subprocess.DEVNULL)
        kernels = result.decode().split('\n')
        installed_kernels = [line for line in kernels if re.match(r'ii\s+linux-image', line)]
        if len(installed_kernels) > 1:
            print("Multiple kernel versions installed:")
            for kernel in installed_kernels:
                print(kernel)
            print("Consider removing old kernels.")
        else:
            print("No old kernels found.")
    except Exception as e:
        print(f"Error checking for old kernels: {e}")

# Function to check for unauthorized SSH keys in authorized_keys
def check_authorized_keys():
    print("Checking for unauthorized SSH keys in users' authorized_keys files...")
    authorized_users = ['admin', 'user1']  # Replace with actual authorized users
    for user in pwd.getpwall():
        home_dir = user.pw_dir
        ssh_dir = os.path.join(home_dir, '.ssh')
        authorized_keys_file = os.path.join(ssh_dir, 'authorized_keys')
        if os.path.exists(authorized_keys_file):
            if user.pw_name not in authorized_users:
                print(f"Unauthorized user {user.pw_name} has SSH authorized_keys file.")
    print("Authorized keys check completed.")

# Function to check for file integrity using package manager
def check_file_integrity():
    print("Checking file integrity using package manager...")
    try:
        result = subprocess.check_output(['debsums', '-s'], stderr=subprocess.DEVNULL)
        if result:
            print("Modified files detected:")
            print(result.decode())
        else:
            print("All files match the package database.")
    except Exception as e:
        print("debsums utility is not installed or an error occurred.")

# Function to check for improper umask settings
def check_umask_settings():
    print("Checking for improper umask settings...")
    try:
        with open('/etc/login.defs', 'r') as file:
            content = file.read()
            umask_match = re.search(r'^\s*UMASK\s+(\d+)', content, re.MULTILINE)
            if umask_match:
                umask = umask_match.group(1)
                if umask != '077':
                    print(f"UMASK is set to {umask}. It should be 077 for maximum security.")
                else:
                    print("UMASK is set correctly.")
            else:
                print("UMASK is not set in /etc/login.defs.")
    except Exception as e:
        print(f"Error checking umask settings: {e}")

# Function to check for dangerous aliases in shell configuration files
def check_shell_aliases():
    print("Checking for dangerous aliases in shell configuration files...")
    shell_configs = ['.bashrc', '.bash_profile', '.profile']
    for user in pwd.getpwall():
        home_dir = user.pw_dir
        for config_file in shell_configs:
            config_path = os.path.join(home_dir, config_file)
            if os.path.exists(config_path):
                with open(config_path, 'r') as file:
                    content = file.read()
                    if 'alias rm=' in content:
                        print(f"Dangerous alias found in {user.pw_name}'s {config_file}")
    print("Shell aliases check completed.")
def check_home_directory_permissions():
    print("Checking permissions of user home directories...")
    for user in pwd.getpwall():
        home_dir = user.pw_dir
        if os.path.isdir(home_dir) and user.pw_uid >= 1000:
            stat_info = os.stat(home_dir)
            permissions = oct(stat_info.st_mode & 0o777)
            if permissions != '0o700' and permissions != '0o750':
                print(f"Home directory {home_dir} has permissions {permissions}. Should be 700 or 750.")
    print("Home directory permissions check completed.")

# Function to check for world-readable private SSH keys
def check_world_readable_private_keys():
    print("Checking for world-readable private SSH keys...")
    command = ['find', '/home', '-type', 'f', '-name', 'id_rsa', '-perm', '-004']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        keys = result.decode().split('\n')
        readable_keys = [k for k in keys if k]
        if readable_keys:
            print("World-readable private SSH keys found:")
            for key in readable_keys:
                print(key)
        else:
            print("No world-readable private SSH keys found.")
    except Exception as e:
        print(f"Error checking private SSH keys: {e}")

# Function to check SELinux or AppArmor status
def check_security_module():
    print("Checking SELinux/AppArmor status...")
    selinux_status = '/sys/fs/selinux/enforce'
    apparmor_status = '/sys/module/apparmor/parameters/enabled'
    if os.path.exists(selinux_status):
        with open(selinux_status, 'r') as file:
            status = file.read().strip()
            if status == '1':
                print("SELinux is enforcing.")
            else:
                print("SELinux is not enforcing.")
    elif os.path.exists(apparmor_status):
        with open(apparmor_status, 'r') as file:
            status = file.read().strip()
            if status == 'Y':
                print("AppArmor is enabled.")
            else:
                print("AppArmor is disabled.")
    else:
        print("No security module (SELinux/AppArmor) is active.")

# Function to check MySQL/MariaDB root account security
def check_mysql_root_access():
    print("Checking MySQL/MariaDB root account security...")
    try:
        import MySQLdb
        db = MySQLdb.connect(user='root')
        cursor = db.cursor()
        cursor.execute("SELECT User, Host FROM mysql.user WHERE User='root';")
        results = cursor.fetchall()
        for user, host in results:
            if host == '%':
                print("MySQL root account is accessible from any host. This is insecure.")
            else:
                print(f"MySQL root account is restricted to host: {host}")
        db.close()
    except ImportError:
        print("MySQLdb module not installed. Skipping MySQL root access check.")
    except Exception as e:
        print("MySQL root access is secure or MySQL is not installed.")

# Function to check for exposed Docker API ports
def check_docker_api():
    print("Checking for exposed Docker API ports...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':2375' in result.decode() or ':2376' in result.decode():
            print("Docker API port is exposed. This can be a security risk.")
        else:
            print("Docker API port is not exposed.")
    except Exception as e:
        print(f"Error checking Docker API ports: {e}")

# Function to check for unrestricted NFS exports
def check_nfs_exports():
    print("Checking NFS exports for unrestricted access...")
    exports_file = '/etc/exports'
    if os.path.exists(exports_file):
        with open(exports_file, 'r') as file:
            exports = file.readlines()
            for line in exports:
                if re.search(r'\*\(.*rw', line):
                    print("NFS export with unrestricted read/write access found:")
                    print(line.strip())
        print("NFS exports check completed.")
    else:
        print("NFS is not installed or /etc/exports file not found.")

# Function to check for weak ciphers in SSH configuration
def check_ssh_weak_ciphers():
    print("Checking SSH configuration for weak ciphers...")
    try:
        with open('/etc/ssh/sshd_config', 'r') as ssh_config:
            config = ssh_config.read()
            if 'Ciphers' not in config:
                print("No specific ciphers are set in SSH configuration. Weak ciphers may be allowed.")
            else:
                print("Specific ciphers are set in SSH configuration.")
    except Exception as e:
        print(f"Error checking SSH ciphers: {e}")

# Function to check PHP configurations for security
def check_php_settings():
    print("Checking PHP configuration for security...")
    php_ini = '/etc/php.ini'
    if not os.path.exists(php_ini):
        php_ini = '/etc/php/7.4/apache2/php.ini'  # Adjust version as needed
    if os.path.exists(php_ini):
        with open(php_ini, 'r') as file:
            config = file.read()
            if 'expose_php = On' in config:
                print("PHP is configured to expose its version. Set expose_php to Off.")
            else:
                print("PHP version exposure is disabled.")
    else:
        print("PHP is not installed or php.ini not found.")

# Function to check for default Apache index pages
def check_default_apache_pages():
    print("Checking for default Apache index pages...")
    web_root = '/var/www/html'
    index_files = ['index.html', 'index.php']
    for file in index_files:
        file_path = os.path.join(web_root, file)
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
                if 'Apache2 Ubuntu Default Page' in content:
                    print(f"Default Apache index page found: {file_path}")
    print("Default Apache pages check completed.")

# Function to check for insecure permissions on log files
def check_log_file_permissions():
    print("Checking permissions on log files...")
    log_files = ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages']
    for log_file in log_files:
        if os.path.exists(log_file):
            stat_info = os.stat(log_file)
            permissions = oct(stat_info.st_mode & 0o777)
            if permissions != '0o600' and permissions != '0o640':
                print(f"Log file {log_file} has permissions {permissions}. Should be 600 or 640.")
    print("Log file permissions check completed.")

# Function to check misconfigured sudoers.d files
def check_sudoers_d():
    print("Checking /etc/sudoers.d for misconfigurations...")
    sudoers_d = '/etc/sudoers.d'
    if os.path.exists(sudoers_d):
        for filename in os.listdir(sudoers_d):
            filepath = os.path.join(sudoers_d, filename)
            with open(filepath, 'r') as file:
                content = file.read()
                if 'NOPASSWD' in content:
                    print(f"NOPASSWD directive found in {filepath}. This may be insecure.")
    print("/etc/sudoers.d check completed.")

# Function to check for missing security updates
def check_security_updates():
    print("Checking for missing security updates...")
    try:
        subprocess.run(['apt-get', 'update'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.check_output(['apt-get', '-s', 'upgrade'], stderr=subprocess.DEVNULL)
        updates = result.decode()
        if 'Inst' in updates:
            print("Security updates are available. Please run apt-get upgrade.")
        else:
            print("No security updates available.")
    except Exception as e:
        print("Error checking for security updates or system is not using apt-get.")

# Function to check auditd status
def check_auditd():
    print("Checking if auditd is installed and running...")
    try:
        result = subprocess.check_output(['systemctl', 'is-active', 'auditd'], stderr=subprocess.DEVNULL)
        status = result.decode().strip()
        if status == 'active':
            print("auditd is installed and running.")
        else:
            print("auditd is not running.")
    except Exception as e:
        print("auditd is not installed or an error occurred.")

# Function to check Redis security settings
def check_redis_security():
    print("Checking Redis security settings...")
    redis_conf = '/etc/redis/redis.conf'
    if os.path.exists(redis_conf):
        with open(redis_conf, 'r') as file:
            config = file.read()
            if 'bind 127.0.0.1' not in config:
                print("Redis is not bound to localhost. It may be accessible remotely.")
            if 'requirepass' not in config:
                print("Redis does not require a password. This is insecure.")
    else:
        print("Redis is not installed or redis.conf not found.")

# Function to check rsync configuration
def check_rsync_configuration():
    print("Checking rsync configuration...")
    rsync_conf = '/etc/rsyncd.conf'
    if os.path.exists(rsync_conf):
        with open(rsync_conf, 'r') as file:
            config = file.read()
            if 'uid = root' in config or 'gid = root' in config:
                print("rsync is running as root. This may be insecure.")
            else:
                print("rsync configuration appears secure.")
    else:
        print("rsyncd.conf not found. rsync may not be configured as a daemon.")

# Function to check Elasticsearch security
def check_elasticsearch():
    print("Checking Elasticsearch configuration...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':9200' in result.decode():
            print("Elasticsearch is running and accessible on port 9200.")
    except Exception as e:
        print("Error checking Elasticsearch or it is not running.")

# Function to check RabbitMQ configurations
def check_rabbitmq():
    print("Checking RabbitMQ configuration...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':5672' in result.decode():
            print("RabbitMQ is running on port 5672.")
            # Further checks would require RabbitMQ utilities
    except Exception as e:
        print("RabbitMQ is not running or an error occurred.")

# Function to check for open MongoDB instances
def check_mongodb():
    print("Checking MongoDB configuration...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':27017' in result.decode():
            print("MongoDB is running and accessible on port 27017.")
    except Exception as e:
        print("MongoDB is not running or an error occurred.")

# Function to check firewalld or iptables status
def check_firewall_status():
    print("Checking firewall status (firewalld or iptables)...")
    try:
        result = subprocess.check_output(['systemctl', 'is-active', 'firewalld'], stderr=subprocess.DEVNULL)
        if result.decode().strip() == 'active':
            print("firewalld is active.")
        else:
            print("firewalld is not active.")
    except Exception:
        try:
            result = subprocess.check_output(['iptables', '-L'], stderr=subprocess.DEVNULL)
            if result:
                print("iptables rules are present.")
            else:
                print("No iptables rules found.")
        except Exception as e:
            print("Neither firewalld nor iptables is active.")

# Function to check for unencrypted sensitive data in config files
def check_sensitive_data_in_configs():
    print("Checking for unencrypted sensitive data in configuration files...")
    config_dirs = ['/etc']
    sensitive_keywords = ['password', 'secret', 'apikey', 'token']
    for dir_path in config_dirs:
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if file.endswith(('.conf', '.ini', '.cfg')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r') as f:
                            content = f.read()
                            for keyword in sensitive_keywords:
                                if keyword in content.lower():
                                    print(f"Sensitive keyword '{keyword}' found in {filepath}")
                    except Exception:
                        continue
    print("Sensitive data check completed.")

# Function to check PAM password policies
def check_pam_password_policy():
    print("Checking PAM password policies...")
    pam_file = '/etc/pam.d/common-password'
    if os.path.exists(pam_file):
        with open(pam_file, 'r') as file:
            content = file.read()
            if 'pam_cracklib.so' not in content and 'pam_pwquality.so' not in content:
                print("PAM password quality module is not configured.")
            else:
                print("PAM password quality module is configured.")
    else:
        print(f"{pam_file} not found.")

# Function to check SNMP configurations
def check_snmp_config():
    print("Checking SNMP configuration...")
    snmp_conf = '/etc/snmp/snmpd.conf'
    if os.path.exists(snmp_conf):
        with open(snmp_conf, 'r') as file:
            content = file.read()
            if 'public' in content or 'private' in content:
                print("Default SNMP community strings found. They should be changed.")
    else:
        print("SNMP is not installed or snmpd.conf not found.")

# Function to check for unsecured VNC servers
def check_vnc_server():
    print("Checking for unsecured VNC servers...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':5900' in result.decode():
            print("VNC server is running on port 5900.")
    except Exception as e:
        print("VNC server is not running or an error occurred.")

# Function to check web server directory listing
def check_directory_listing():
    print("Checking for directory listing enabled on web server...")
    apache_conf_dirs = ['/etc/apache2/sites-enabled', '/etc/httpd/conf.d']
    for conf_dir in apache_conf_dirs:
        if os.path.exists(conf_dir):
            for filename in os.listdir(conf_dir):
                filepath = os.path.join(conf_dir, filename)
                with open(filepath, 'r') as file:
                    content = file.read()
                    if 'Options Indexes' in content:
                        print(f"Directory listing is enabled in {filepath}")
    print("Directory listing check completed.")

# Function to check Jenkins security
def check_jenkins():
    print("Checking if Jenkins is installed and secured...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':8080' in result.decode():
            print("Jenkins is running on port 8080.")
            # Additional checks would require Jenkins CLI or API
    except Exception as e:
        print("Jenkins is not running or an error occurred.")

# Function to check Kubernetes cluster security
def check_kubernetes():
    print("Checking for Kubernetes cluster...")
    kube_config = '/etc/kubernetes/admin.conf'
    if os.path.exists(kube_config):
        print("Kubernetes cluster detected.")
        # Additional security checks require kubectl and cluster access
    else:
        print("Kubernetes is not installed.")

# Function to check SSL/TLS configurations
def check_ssl_tls_configuration():
    print("Checking SSL/TLS configurations...")
    ssl_conf = '/etc/ssl/openssl.cnf'
    if os.path.exists(ssl_conf):
        with open(ssl_conf, 'r') as file:
            content = file.read()
            if 'SSLProtocol all -SSLv2 -SSLv3' not in content:
                print("Weak SSL/TLS protocols may be enabled.")
    else:
        print("OpenSSL configuration file not found.")

# Function to check for unsecured memcached servers
def check_memcached():
    print("Checking for unsecured memcached server...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':11211' in result.decode():
            print("Memcached is running and may be unsecured.")
    except Exception as e:
        print("Memcached is not running or an error occurred.")

# Function to check OpenVPN configurations
def check_openvpn():
    print("Checking OpenVPN configuration...")
    openvpn_conf = '/etc/openvpn/server.conf'
    if os.path.exists(openvpn_conf):
        with open(openvpn_conf, 'r') as file:
            content = file.read()
            if 'cipher AES-256-CBC' not in content:
                print("OpenVPN is not using strong cipher AES-256-CBC.")
    else:
        print("OpenVPN is not installed or server.conf not found.")

# Function to check default configurations in Tomcat
def check_tomcat_configuration():
    print("Checking Apache Tomcat configuration...")
    tomcat_users = '/etc/tomcat9/tomcat-users.xml'
    if os.path.exists(tomcat_users):
        with open(tomcat_users, 'r') as file:
            content = file.read()
            if '<user username="admin" password="admin"' in content:
                print("Default Tomcat admin user detected. This is insecure.")
    else:
        print("Tomcat is not installed or tomcat-users.xml not found.")

# Function to check for unnecessary services enabled at startup
def check_startup_services():
    print("Checking for unnecessary services enabled at startup...")
    try:
        result = subprocess.check_output(['systemctl', 'list-unit-files', '--type=service'], stderr=subprocess.DEVNULL)
        services = result.decode().split('\n')
        unwanted_services = ['telnet.service', 'nfs.service', 'rsh.service']
        for service in services:
            for unwanted in unwanted_services:
                if unwanted in service and 'enabled' in service:
                    print(f"Unnecessary service {unwanted} is enabled at startup.")
    except Exception as e:
        print(f"Error checking startup services: {e}")

# Function to check for misconfigured DNS settings
def check_dns_settings():
    print("Checking DNS settings...")
    resolv_conf = '/etc/resolv.conf'
    if os.path.exists(resolv_conf):
        with open(resolv_conf, 'r') as file:
            content = file.read()
            if 'nameserver 127.0.0.1' in content:
                print("DNS is set to localhost. Ensure this is intended.")
            else:
                print("DNS settings appear normal.")
    else:
        print("/etc/resolv.conf not found.")

# Function to check for unsecure mail services
def check_mail_services():
    print("Checking mail services for security...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':25' in result.decode():
            print("SMTP service is running on port 25.")
            # Further checks would require examining mail server configuration
    except Exception as e:
        print("Mail services are not running or an error occurred.")

# Function to check for unencrypted LDAP connections
def check_ldap_connections():
    print("Checking for unencrypted LDAP connections...")
    try:
        result = subprocess.check_output(['ss', '-tuln'], stderr=subprocess.DEVNULL)
        if ':389' in result.decode():
            print("LDAP service is running on port 389 without encryption.")
    except Exception as e:
        print("LDAP is not running or an error occurred.")

def ensure_ipv6_disabled():
    print("Ensuring IPv6 is disabled...")
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'r') as file:
            status = file.read().strip()
            if status == '1':
                print("IPv6 is already disabled.")
            else:
                print("IPv6 is enabled. It should be disabled according to policy.")
    except FileNotFoundError:
        print("IPv6 configuration file not found. IPv6 may not be supported.")

# Function to enforce password complexity requirements
def enforce_password_complexity():
    print("Checking password complexity enforcement...")
    pam_pwquality_files = ['/etc/pam.d/common-password', '/etc/pam.d/system-auth']
    for pam_file in pam_pwquality_files:
        if os.path.exists(pam_file):
            with open(pam_file, 'r') as file:
                content = file.read()
                if 'pam_pwquality.so' in content or 'pam_cracklib.so' in content:
                    print(f"Password complexity is enforced in {pam_file}.")
                else:
                    print(f"Password complexity is not enforced in {pam_file}.")
    print("Password complexity check completed.")

# Function to ensure password expiration is set
def check_password_expiration():
    print("Checking password expiration settings...")
    try:
        with open('/etc/login.defs', 'r') as file:
            content = file.read()
            max_days = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
            if max_days:
                days = int(max_days.group(1))
                if days > 90:
                    print(f"PASS_MAX_DAYS is set to {days}. It should be 90 or less.")
                else:
                    print(f"PASS_MAX_DAYS is set to {days}.")
            else:
                print("PASS_MAX_DAYS is not set.")
    except Exception as e:
        print(f"Error checking password expiration: {e}")

# Function to check for unauthorized user accounts
def check_unauthorized_users():
    print("Checking for unauthorized user accounts...")
    authorized_users = ['root', 'admin', 'vought_user']  # Update with actual authorized users
    system_users = [user.pw_name for user in pwd.getpwall() if user.pw_uid < 1000]
    unauthorized_users = [user.pw_name for user in pwd.getpwall() if user.pw_name not in authorized_users and user.pw_uid >= 1000]
    if unauthorized_users:
        print("Unauthorized user accounts found: ", unauthorized_users)
    else:
        print("No unauthorized user accounts found.")
    print("Unauthorized user accounts check completed.")

# Function to ensure remote access is properly configured
def check_remote_access():
    print("Ensuring remote access is properly configured...")
    ssh_config_file = '/etc/ssh/sshd_config'
    if os.path.exists(ssh_config_file):
        with open(ssh_config_file, 'r') as file:
            content = file.read()
            if 'PasswordAuthentication yes' in content:
                print("SSH password authentication is enabled.")
            else:
                print("SSH password authentication is disabled.")
            if 'PermitRootLogin no' in content:
                print("Root login over SSH is disabled.")
            else:
                print("Root login over SSH is enabled. It should be disabled for security.")
    else:
        print("SSH configuration file not found.")
    print("Remote access configuration check completed.")

# Function to check if critical services are running
def check_critical_services():
    print("Checking if critical services are running...")
    critical_services = ['ssh', 'smbd', 'apache2']  # Update based on your services
    for service in critical_services:
        result = subprocess.run(['systemctl', 'is-active', service], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"Service {service} is running.")
        else:
            print(f"Service {service} is not running. It should be started.")
    print("Critical services check completed.")

# Function to ensure that only authorized files are present in critical directories
def check_critical_directories():
    print("Checking critical directories for unauthorized files...")
    critical_directories = ['/var/www/html', '/etc/samba']
    allowed_files = {
        '/var/www/html': ['index.html', 'index.php'],
        '/etc/samba': ['smb.conf']
    }
    for directory in critical_directories:
        if os.path.exists(directory):
            files = os.listdir(directory)
            unauthorized_files = [f for f in files if f not in allowed_files.get(directory, [])]
            if unauthorized_files:
                print(f"Unauthorized files found in {directory}: {unauthorized_files}")
            else:
                print(f"No unauthorized files in {directory}.")
        else:
            print(f"Directory {directory} does not exist.")
    print("Critical directories check completed.")

# Function to verify that no unauthorized software is installed
def check_installed_software():
    print("Checking for unauthorized installed software...")
    unauthorized_packages = ['netcat', 'nmap', 'hydra', 'john']
    installed_packages = []
    for package in unauthorized_packages:
        result = subprocess.run(['dpkg', '-l', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            installed_packages.append(package)
    if installed_packages:
        print("Unauthorized software installed: ", installed_packages)
    else:
        print("No unauthorized software installed.")
    print("Installed software check completed.")

# Function to ensure that unauthorized media files are not present
def check_for_media_files():
    print("Checking for unauthorized media files...")
    media_extensions = ['.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac']
    unauthorized_files = []
    for root_dir in ['/home', '/var']:
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                if any(file.endswith(ext) for ext in media_extensions):
                    unauthorized_files.append(os.path.join(root, file))
    if unauthorized_files:
        print("Unauthorized media files found:")
        for file in unauthorized_files:
            print(file)
    else:
        print("No unauthorized media files found.")
    print("Media files check completed.")

# Function to check that critical services are not accessible from unauthorized networks
def check_service_access():
    print("Checking service access restrictions...")
    # Assuming we need to ensure services are accessible from any public IP as per policy
    print("Services are required to be accessible from any public IP. Ensure firewall allows this.")
    # You can implement specific checks based on your firewall configuration
    print("Service access check completed.")

# Function to ensure that no prohibited files are present in critical service directories
def check_prohibited_files_in_services():
    print("Checking for prohibited files in service directories...")
    service_directories = ['/var/www/html', '/etc/samba']
    prohibited_files = ['.htaccess', '.htpasswd', 'backup.zip']
    for directory in service_directories:
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file in prohibited_files:
                        print(f"Prohibited file {file} found in {root}.")
    print("Prohibited files in services check completed.")

# Function to check for weak or default SSH host keys
def check_ssh_host_keys():
    print("Checking SSH host keys for default or weak keys...")
    key_files = ['/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_ecdsa_key', '/etc/ssh/ssh_host_ed25519_key']
    for key_file in key_files:
        if os.path.exists(key_file):
            with open(key_file, 'rb') as file:
                key_data = file.read()
                key_size = len(key_data) * 8  # Approximate key size
                if key_size < 2048:
                    print(f"Weak SSH host key detected: {key_file}")
    print("SSH host keys check completed.")

# Function to verify that Samba shares are properly configured
def check_samba_shares():
    print("Verifying Samba shares configuration...")
    smb_conf = '/etc/samba/smb.conf'
    if os.path.exists(smb_conf):
        with open(smb_conf, 'r') as file:
            content = file.read()
            shares = re.findall(r'\[([^\]]+)\]', content)
            for share in shares:
                if share.lower() == 'global':
                    continue
                if 'guest ok = yes' in content:
                    print(f"Samba share {share} allows guest access. This should be disabled.")
    else:
        print("Samba configuration file not found.")
    print("Samba shares check completed.")

# Function to ensure that Apache is configured securely
def check_apache_configuration():
    print("Checking Apache configuration for security...")
    apache_conf = '/etc/apache2/apache2.conf'
    if os.path.exists(apache_conf):
        with open(apache_conf, 'r') as file:
            content = file.read()
            if 'ServerTokens Prod' not in content:
                print("Apache is not configured to hide version information (ServerTokens).")
            if 'ServerSignature Off' not in content:
                print("Apache is not configured to hide server signature (ServerSignature).")
    else:
        print("Apache configuration file not found.")
    print("Apache configuration check completed.")

# Function to check that firewall rules meet the policy
def check_firewall_policy():
    print("Checking firewall rules to ensure compliance with policy...")
    # Assuming ufw is used
    try:
        result = subprocess.check_output(['ufw', 'status'], stderr=subprocess.DEVNULL)
        status = result.decode()
        if 'Status: inactive' in status:
            print("Firewall is inactive. It should be active according to policy.")
        else:
            print("Firewall is active. Ensure rules comply with policy.")
    except Exception as e:
        print("Firewall status could not be determined.")
    print("Firewall policy check completed.")

# Function to ensure that system time is synchronized
def check_time_synchronization():
    print("Checking if system time is synchronized...")
    try:
        result = subprocess.check_output(['timedatectl'], stderr=subprocess.DEVNULL)
        output = result.decode()
        if 'NTP synchronized: yes' in output:
            print("System time is synchronized with NTP.")
        else:
            print("System time is not synchronized with NTP.")
    except Exception as e:
        print("Error checking time synchronization.")
    print("Time synchronization check completed.")

# Function to check that logrotate is configured
def check_logrotate():
    print("Checking if logrotate is configured...")
    logrotate_conf = '/etc/logrotate.conf'
    if os.path.exists(logrotate_conf):
        print("Logrotate is configured.")
    else:
        print("Logrotate is not configured.")
    print("Logrotate check completed.")

# Function to ensure that unnecessary services are disabled
def check_disabled_services():
    print("Checking for unnecessary services that should be disabled...")
    unnecessary_services = ['telnet', 'rsh', 'rexec', 'finger']
    for service in unnecessary_services:
        result = subprocess.run(['systemctl', 'is-active', service], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"Service {service} is running. It should be disabled.")
        else:
            print(f"Service {service} is not running.")
    print("Disabled services check completed.")

# Function to check for the presence of auditd
def check_auditd_presence():
    print("Checking if auditd is installed and running...")
    result = subprocess.run(['systemctl', 'is-active', 'auditd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print("auditd is installed and running.")
    else:
        print("auditd is not installed or not running. It should be installed according to policy.")
    print("auditd presence check completed.")

# Function to ensure that no duplicate SSH keys exist
def check_duplicate_ssh_keys():
    print("Checking for duplicate SSH keys among users...")
    ssh_keys = {}
    for user in pwd.getpwall():
        home_dir = user.pw_dir
        authorized_keys_file = os.path.join(home_dir, '.ssh', 'authorized_keys')
        if os.path.exists(authorized_keys_file):
            with open(authorized_keys_file, 'r') as file:
                keys = file.readlines()
                for key in keys:
                    key_fingerprint = hashlib.md5(key.encode()).hexdigest()
                    if key_fingerprint in ssh_keys:
                        print(f"Duplicate SSH key found for user {user.pw_name}")
                    else:
                        ssh_keys[key_fingerprint] = user.pw_name
    print("Duplicate SSH keys check completed.")

# Function to verify that no users have empty passwords
def check_no_empty_passwords():
    print("Ensuring no users have empty passwords...")
    with open('/etc/shadow', 'r') as shadow_file:
        for line in shadow_file:
            parts = line.strip().split(':')
            if len(parts) > 1:
                username = parts[0]
                password_hash = parts[1]
                if password_hash == '':
                    print(f"User {username} has an empty password.")
    print("Empty passwords check completed.")

# Function to ensure that important files are not world-writable
def check_important_files_permissions():
    print("Checking permissions of important files...")
    important_files = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow']
    for file in important_files:
        if os.path.exists(file):
            stat_info = os.stat(file)
            permissions = oct(stat_info.st_mode & 0o777)
            if permissions[-1] in ['2', '3', '6', '7']:
                print(f"File {file} is world-writable. Permissions: {permissions}")
    print("Important files permissions check completed.")

# Function to check for unauthorized scheduled tasks
def check_scheduled_tasks():
    print("Checking for unauthorized scheduled tasks...")
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly']
    authorized_scripts = ['logrotate', 'apt', 'ntp']
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            for script in os.listdir(cron_dir):
                if script not in authorized_scripts:
                    print(f"Unauthorized scheduled task found: {script} in {cron_dir}")
    print("Scheduled tasks check completed.")

# Function to ensure that the system does not have unauthorized kernel modules loaded
def check_kernel_modules():
    print("Checking for unauthorized kernel modules...")
    loaded_modules = subprocess.check_output(['lsmod'], stderr=subprocess.DEVNULL).decode().split('\n')
    unauthorized_modules = ['firewire_ohci', 'bluetooth', 'usb_storage']
    for module_line in loaded_modules:
        module = module_line.split()[0] if module_line else ''
        if module in unauthorized_modules:
            print(f"Unauthorized kernel module loaded: {module}")
    print("Kernel modules check completed.")

# Function to ensure that DNS settings are configured correctly
def check_dns_configuration():
    print("Checking DNS configuration...")
    resolv_conf = '/etc/resolv.conf'
    if os.path.exists(resolv_conf):
        with open(resolv_conf, 'r') as file:
            content = file.read()
            if 'nameserver' not in content:
                print("No DNS nameservers configured in /etc/resolv.conf")
    else:
        print("/etc/resolv.conf not found.")
    print("DNS configuration check completed.")

# Function to check for outdated software versions
def check_outdated_software():
    print("Checking for outdated software packages...")
    try:
        subprocess.run(['apt-get', 'update'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.check_output(['apt-get', '-s', 'upgrade'], stderr=subprocess.DEVNULL)
        upgrades = result.decode()
        if 'upgraded' in upgrades:
            print("There are software packages that need to be updated.")
        else:
            print("All software packages are up to date.")
    except Exception as e:
        print("Error checking for software updates.")
    print("Outdated software check completed.")

# Function to ensure that the system has proper banner messages
def check_banner_messages():
    print("Checking for proper banner messages...")
    issue_file = '/etc/issue.net'
    motd_file = '/etc/motd'
    required_banner = "Authorized users only. All activity may be monitored and reported."
    for file in [issue_file, motd_file]:
        if os.path.exists(file):
            with open(file, 'r') as f:
                content = f.read()
                if required_banner not in content:
                    print(f"Banner message in {file} does not meet the policy.")
    print("Banner messages check completed.")

# Function to ensure that system audit logs are not world-readable
def check_audit_log_permissions():
    print("Checking permissions of audit logs...")
    audit_log = '/var/log/audit/audit.log'
    if os.path.exists(audit_log):
        stat_info = os.stat(audit_log)
        permissions = oct(stat_info.st_mode & 0o777)
        if permissions != '0o600':
            print(f"Audit log {audit_log} has permissions {permissions}. Should be 600.")
    else:
        print("Audit log file not found.")
    print("Audit log permissions check completed.")

# Function to verify that system files have not been tampered with
def check_file_integrity():
    print("Verifying integrity of system files...")
    # Assuming AIDE (Advanced Intrusion Detection Environment) is installed
    aide_conf = '/etc/aide/aide.conf'
    if os.path.exists(aide_conf):
        result = subprocess.run(['aide', '--check'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        if 'changed files' in output:
            print("File integrity issues detected by AIDE.")
        else:
            print("File integrity verified by AIDE.")
    else:
        print("AIDE is not installed.")
    print("File integrity check completed.")

# Function to ensure that SSH idle timeout is set
def check_ssh_idle_timeout():
    print("Checking SSH idle timeout settings...")
    ssh_config_file = '/etc/ssh/sshd_config'
    if os.path.exists(ssh_config_file):
        with open(ssh_config_file, 'r') as file:
            content = file.read()
            if 'ClientAliveInterval' not in content or 'ClientAliveCountMax' not in content:
                print("SSH idle timeout is not configured.")
            else:
                print("SSH idle timeout is configured.")
    else:
        print("SSH configuration file not found.")
    print("SSH idle timeout check completed.")

# Function to ensure that system accounts are non-login
def check_system_accounts():
    print("Ensuring system accounts are non-login...")
    for user in pwd.getpwall():
        if user.pw_uid < 1000 and user.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
            print(f"System account {user.pw_name} has login shell {user.pw_shell}. It should be nologin or false.")
    print("System accounts check completed.")
# Main function to run all checks
def main():
    check_root()
    check_weak_passwords()
    check_empty_passwords()
    check_password_policy()
    check_media_files()
    check_hacking_tools()
    check_ipv6()
    check_ssh_config()
    check_samba_config()
    check_outdated_packages()
    check_firewall()
    check_services()
    check_uid_zero_users()
    check_world_writable_files()
    check_root_home_permissions()
    check_root_cron()
    check_suid_sgid_files()
    check_shell_access_users()
    check_duplicate_ids()
    check_passwd_hashes()
    check_sudoers()
    check_open_ports()
    check_critical_file_permissions()
    check_root_owned_files_in_home()
    check_world_writable_directories()
    check_services_running_as_root()
    check_weak_ssh_keys()
    check_ftp_service()
    check_anonymous_ftp()
    check_core_dumps()
    check_firewall_rules()
    check_cron_permissions()
    check_path_variable()
    check_snmp_settings()
    check_kernel_modules()
    check_logging()
    check_empty_groups()
    check_ntp_config()
    check_mail_relay()
    check_x11_forwarding()
    check_rhosts_files()
    check_ssh_host_keys()
    check_unowned_files()
    check_listening_processes()
    check_unnecessary_packages()
    check_default_accounts()
    check_backup_files()
    check_old_kernels()
    check_authorized_keys()
    check_file_integrity()
    check_umask_settings()
    check_shell_aliases()
    check_home_directory_permissions()
    check_world_readable_private_keys()
    check_security_module()
    check_mysql_root_access()
    check_docker_api()
    check_nfs_exports()
    check_ssh_weak_ciphers()
    check_php_settings()
    check_default_apache_pages()
    check_log_file_permissions()
    check_sudoers_d()
    check_security_updates()
    check_auditd()
    check_redis_security()
    check_rsync_configuration()
    check_elasticsearch()
    check_rabbitmq()
    check_mongodb()
    check_firewall_status()
    check_sensitive_data_in_configs()
    check_pam_password_policy()
    check_snmp_config()
    check_vnc_server()
    check_directory_listing()
    check_jenkins()
    check_kubernetes()
    check_ssl_tls_configuration()
    check_memcached()
    check_openvpn()
    check_tomcat_configuration()
    check_startup_services()
    check_dns_settings()
    check_mail_services()
    check_ldap_connections()
    ensure_ipv6_disabled()
    enforce_password_complexity()
    check_password_expiration()
    check_unauthorized_users()
    check_remote_access()
    check_critical_services()
    check_critical_directories()
    check_installed_software()
    check_for_media_files()
    check_service_access()
    check_prohibited_files_in_services()
    check_ssh_host_keys()
    check_samba_shares()
    check_apache_configuration()
    check_firewall_policy()
    check_time_synchronization()
    check_logrotate()
    check_disabled_services()
    check_auditd_presence()
    check_duplicate_ssh_keys()
    check_no_empty_passwords()
    check_important_files_permissions()
    check_scheduled_tasks()
    check_kernel_modules()
    check_dns_configuration()
    check_outdated_software()
    check_banner_messages()
    check_audit_log_permissions()
    check_file_integrity()
    check_ssh_idle_timeout()
    check_system_accounts()
    print("Security audit completed.")

if __name__ == "__main__":
    main()
