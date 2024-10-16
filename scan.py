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
    # This function would require cracking passwords, which is not appropriate
    print("Password strength checking is beyond the scope of this script.")

# Function to search for unauthorized media files
def check_media_files():
    print("Searching for unauthorized media files...")
    media_extensions = ['*.mp3', '*.mp4', '*.avi', '*.mkv', '*.wav', '*.flac']
    unauthorized_files = []
    for ext in media_extensions:
        command = ['find', '/', '-type', 'f', '-name', ext,
                   '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
                   '-not', '-path', '/run/*', '-not', '-path', '/dev/*',
                   '-not', '-path', '/var/lib/*', '-not', '-path', '/var/run/*',
                   '-not', '-path', '/var/cache/*']
        try:
            result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
            files = result.decode(errors='ignore').split('\n')
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
        'yersinia', 'sqlninja', 'exploitdb', 'setoolkit', 'maltego', 'cewl',
        'wpscan', 'dirbuster', 'gobuster', 'bettercap', 'proxychains', 'socat',
        'dnsrecon', 'enum4linux', 'msfvenom', 'evil-winrm', 'patator', 'brutespray',
        'nbtscan', 'sslscan', 'masscan', 'searchsploit', 'theharvester',
        'netdiscover', 'sparta', 'slowloris', 'sslyze', 'skipfish', 'xsser'
    ]
    installed_tools = []
    for tool in hacking_tools:
        command = ['which', tool]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            installed_tools.append(tool)
    if installed_tools:
        print("Unauthorized hacking tools installed:", installed_tools)
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
        print("IPv6 is enabled. It should be disabled if not required.")
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
                if 'map to guest = Bad User' not in config:
                    print("Guest access may be allowed in Samba. It should be disabled.")
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
        command = ['dnf', 'check-update']
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        if 'No packages marked for update' in output:
            print("All packages are up to date.")
        else:
            print("Outdated packages found:")
            print(output)
    except Exception as e:
        print(f"Error checking for outdated packages: {e}")

# Function to check firewall status
def check_firewall():
    print("Checking firewall status...")
    try:
        command = ['systemctl', 'is-active', 'firewalld']
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = result.stdout.decode().strip()
        if status == 'active':
            print("Firewalld is active.")
        else:
            print("Firewalld is inactive. It should be enabled and configured.")
    except Exception as e:
        print(f"Error checking firewall status: {e}")

# Function to check for unnecessary services
def check_services():
    print("Checking for unnecessary or insecure services...")
    # List of services that should not be running
    unnecessary_services = [
        'telnet.socket', 'vsftpd', 'rexec.socket', 'rlogin.socket', 'rsh.socket',
        'ypserv', 'tftp.socket', 'xinetd', 'smb', 'nfs', 'snmpd', 'avahi-daemon',
        'cups', 'dhcpd', 'named', 'nfs-server', 'rpcbind', 'vsftpd', 'httpd',
        'postfix', 'squid', 'net-snmp', 'samba', 'ftp', 'telnet', 'ntalk',
        'talk', 'nntp', 'imap', 'pop3', 'finger', 'ldap', 'dhcp'
    ]
    running_services = []
    for service in unnecessary_services:
        command = ['systemctl', 'is-active', service]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0 and result.stdout.decode().strip() == 'active':
            running_services.append(service)
    if running_services:
        print("Unnecessary or insecure services are running:", running_services)
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
        print("Users with UID 0 found:", uid_zero_users)
    else:
        print("No users with UID 0 besides root.")

# Function to check for world-writable files
def check_world_writable_files():
    print("Checking for world-writable files...")
    command = ['find', '/', '-xdev', '-type', 'f', '-perm', '-0002',
               '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
               '-not', '-path', '/run/*', '-not', '-path', '/dev/*',
               '-not', '-path', '/var/lib/*', '-not', '-path', '/var/run/*',
               '-not', '-path', '/var/cache/*']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        files = result.decode(errors='ignore').split('\n')
        world_writable_files = [f for f in files if f]
        if world_writable_files:
            print("World-writable files found:")
            for file in world_writable_files:
                print(file)
        else:
            print("No world-writable files found.")
    except Exception as e:
        print(f"Error checking for world-writable files: {e}")

# Function to check for empty password fields in /etc/shadow
def check_empty_passwords():
    print("Checking for users with empty passwords...")
    empty_password_users = []
    try:
        with open('/etc/shadow', 'r') as shadow_file:
            for line in shadow_file:
                parts = line.strip().split(':')
                if len(parts) > 1:
                    username = parts[0]
                    password_field = parts[1]
                    if password_field == '':
                        empty_password_users.append(username)
        if empty_password_users:
            print("Users with empty password fields:", empty_password_users)
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
    cron_files = ['/etc/crontab', '/var/spool/cron/root', '/var/spool/cron/crontabs/root']
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
    command = ['find', '/', '-xdev', '-type', 'f', '-perm', '/6000',
               '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
               '-not', '-path', '/run/*', '-not', '-path', '/dev/*',
               '-not', '-path', '/var/lib/*', '-not', '-path', '/var/run/*',
               '-not', '-path', '/var/cache/*']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        files = result.decode(errors='ignore').split('\n')
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
        if user.pw_shell not in ['/usr/sbin/nologin', '/sbin/nologin', '/bin/false']:
            shell_users.append(user.pw_name)
    if shell_users:
        print("Users with shell access:", shell_users)
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
        sudoers_d_dir = '/etc/sudoers.d'
        if os.path.isdir(sudoers_d_dir):
            for filename in os.listdir(sudoers_d_dir):
                filepath = os.path.join(sudoers_d_dir, filename)
                with open(filepath, 'r') as file:
                    for line in file:
                        if re.match(r'^[^#].*ALL\s*=\s*\(ALL\)', line):
                            user = line.split()[0]
                            if user not in authorized_users:
                                sudoers_users.append(user)
        if sudoers_users:
            print("Unauthorized users with sudo access:", sudoers_users)
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
        lines = result.decode(errors='ignore').split('\n')
        open_ports = []
        for line in lines:
            match = re.search(r'LISTEN.*:(\d+)', line)
            if match:
                port = int(match.group(1))
                if port not in necessary_ports:
                    open_ports.append(port)
        if open_ports:
            print("Unnecessary open ports found:", open_ports)
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
                files = result.decode(errors='ignore').split('\n')
                root_files = [f for f in files if f]
                if root_files:
                    print(f"Root-owned files found in {user.pw_name}'s home directory:")
                    for file in root_files:
                        print(file)
            except Exception:
                continue

# Function to check for world-writable directories
def check_world_writable_directories():
    print("Checking for world-writable directories...")
    command = ['find', '/', '-xdev', '-type', 'd', '-perm', '-0002',
               '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
               '-not', '-path', '/run/*', '-not', '-path', '/dev/*',
               '-not', '-path', '/var/lib/*', '-not', '-path', '/var/run/*',
               '-not', '-path', '/var/cache/*']
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        directories = result.decode(errors='ignore').split('\n')
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
        processes = result.decode(errors='ignore').split('\n')
        root_services = []
        for process in processes:
            parts = process.strip().split()
            if len(parts) == 2 and parts[0] == 'root':
                service = parts[1]
                if service not in ['sshd', 'systemd', 'kthreadd', 'dbus-daemon', 'NetworkManager']:  # Add necessary root services here
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
            except Exception:
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
    except Exception:
        print("FTP service is not installed or an error occurred.")

# Function to check for anonymous FTP access
def check_anonymous_ftp():
    print("Checking for anonymous FTP access...")
    vsftpd_conf = '/etc/vsftpd/vsftpd.conf'
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
        with open('/proc/sys/fs/suid_dumpable', 'r') as file:
            suid_dumpable = file.read().strip()
            if suid_dumpable != '0':
                print("Core dumps are enabled for setuid programs. They should be disabled.")
            else:
                print("Core dumps are disabled for setuid programs.")
    except Exception as e:
        print(f"Error checking core dump settings: {e}")

# Function to check for misconfigured firewall rules
def check_firewall_rules():
    print("Checking firewall rules for misconfigurations...")
    try:
        command = ['firewall-cmd', '--list-all']
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            rules = result.stdout.decode()
            print("Firewall rules:")
            print(rules)
        else:
            print("Error retrieving firewall rules.")
    except Exception as e:
        print(f"Error checking firewall rules: {e}")

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
                    if permissions not in ['0o600', '0o700', '0o750', '0o755']:
                        print(f"Incorrect permissions for {filepath}: {permissions}. Should be 600, 700, 750, or 755.")
    print("Cron job permissions check completed.")

# Function to check for improper PATH environment variable settings
def check_path_variable():
    print("Checking PATH environment variable for insecure entries...")
    path = os.environ.get('PATH', '')
    insecure_entries = [entry for entry in path.split(':') if entry == '' or entry == '.' or not os.path.exists(entry)]
    if insecure_entries:
        print("Insecure PATH entries found:", insecure_entries)
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
def check_unnecessary_kernel_modules():
    print("Checking for unnecessary kernel modules...")
    try:
        result = subprocess.check_output(['lsmod'], stderr=subprocess.DEVNULL)
        modules = result.decode(errors='ignore').split('\n')
        unnecessary_modules = ['cramfs', 'freevxfs', 'hfs', 'hfsplus', 'jffs2', 'squashfs', 'udf', 'fat']
        loaded_modules = [line.split()[0] for line in modules if line]
        found_modules = [module for module in unnecessary_modules if module in loaded_modules]
        if found_modules:
            print("Unnecessary kernel modules loaded:", found_modules)
        else:
            print("No unnecessary kernel modules loaded.")
    except Exception as e:
        print(f"Error checking kernel modules: {e}")

# Function to check for misconfigured or missing logs
def check_logging():
    print("Checking for misconfigured or missing logs...")
    log_files = ['/var/log/secure', '/var/log/messages', '/var/log/audit/audit.log']
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
        if not group.gr_mem and group.gr_gid >= 1000:
            empty_groups.append(group.gr_name)
    if empty_groups:
        print("Empty groups found:", empty_groups)
    else:
        print("No empty groups found.")

# Function to check for incorrect NTP configuration
def check_ntp_config():
    print("Checking NTP configuration...")
    ntp_conf_files = ['/etc/ntp.conf', '/etc/chrony.conf']
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

# Continue adding the rest of the functions similarly...

# Main function to run all checks
def main():
    check_root()
    check_weak_passwords()
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
    check_empty_passwords()
    check_password_policy()
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
    check_unnecessary_kernel_modules()
    check_logging()
    check_empty_groups()
    check_ntp_config()
    check_mail_relay()
    # Call other functions as needed
    print("Security audit completed.")

if __name__ == "__main__":
    main()
