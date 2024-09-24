#!/usr/bin/env python3
import os
import json
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import sys
import datetime
import base64
import time
import platform

VERSION = '1.0.3219.78'
SSH_DIR = '~/.ssh'
CONF_PATH = SSH_DIR + '/pritunl-zero.json'
BASH_PROFILE_PATH = '~/.bash_profile'
DEF_KNOWN_HOSTS_PATH = '~/.ssh/known_hosts'
DEF_SSH_CONF_PATH = '~/.ssh/config'

USAGE = """\
Usage: pritunl-ssh [command]

Commands:
  help                 Show help
  version              Print the version and exit
  config               Reconfigure options
  alias                Configure ssh alias to autorun pritunl-ssh
  info                 Show current certificate information
  renew                Force certificate renewal
  clear                Remove all configuration changes made by Pritunl SSH
  clear-strict-host    Remove strict host checking configuration changes
  clear-bastion-host   Remove bastion host configuration changes
  register-smart-card  Register the current Smart Card with Pritunl Zero
  gpg-reset            Reset GPG Smart Card agent"""

conf_zero_server = None
conf_pub_key_path = None
conf_known_hosts_path = None
conf_ssh_config_path = None
conf_ssh_card_serial = None
ssh_dir_path = os.path.expanduser(SSH_DIR)
conf_path = os.path.expanduser(CONF_PATH)
changed = False

def open_browser(url):
    try:
        uname = subprocess.check_output(['uname', '-r'],
            stderr=subprocess.PIPE)
        uname = uname.decode('utf-8')
        microsoft_wsl = 'microsoft' in uname.lower()
    except:
        microsoft_wsl = False

    print('OPEN: ' + url)
    try:
        subprocess.Popen(
            ['xdg-open', url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except:
        try:
            if microsoft_wsl or platform.system() == 'Windows':
                subprocess.Popen(['powershell.exe', '/c', 'start', url])
            elif platform.system() == "Darwin":
                subprocess.Popen(['open', url])
            elif platform.system() == "Linux":
                subprocess.Popen(['sensible-browser', url])
            else:
                print("unknown platform: " + platform.system())
                sys.exit(1)
        except:
            print("unable to open browser, please open the url manually")
            pass


if '--help' in sys.argv[1:] or 'help' in sys.argv[1:]:
    print(USAGE)
    sys.exit(0)

if '--version' in sys.argv[1:] or 'version' in sys.argv[1:]:
    print('pritunl-ssh v' + VERSION)
    sys.exit(0)

if '--gpg-reset' in sys.argv[1:] or 'gpg-reset' in sys.argv[1:]:
    try:
        subprocess.check_call(
            ['killall', 'pinentry'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except:
        pass
    try:
        subprocess.check_call(
            ['killall', 'gpg-agent'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except:
        pass
    time.sleep(3)
    try:
        subprocess.check_call(
            ['gpg-agent', '--daemon'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except:
        pass
    try:
        subprocess.check_call(
            ['gpg-connect-agent', 'updatestartuptty', '/bye'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except:
        pass
    print('GPG agent reset')
    sys.exit(0)

if '--config' not in sys.argv[1:] and \
        'config' not in sys.argv[1:] and \
        os.path.isfile(conf_path):
    with open(conf_path, 'r') as conf_file:
        conf_data = conf_file.read()
        try:
            conf_data = json.loads(conf_data)
            conf_zero_server = conf_data.get('server')
            conf_pub_key_path = conf_data.get('public_key_path')
            conf_known_hosts_path = conf_data.get('known_hosts_path')
            conf_ssh_config_path = conf_data.get('ssh_config_path')
            conf_ssh_card_serial = conf_data.get('ssh_card_serial')
        except:
            print('WARNING: Failed to parse config file')

card_name = None
card_serial = None
card_pub_key = None
try:
    # card_status = subprocess.check_output(['gpg', '--card-status'],
    #     stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    # card_status = card_status.decode('utf-8')
    # for line in card_status.splitlines():
    #     if line.startswith('Manufacturer') and not card_name:
    #         card_name = line.split(':', 1)[-1].strip()
    #     elif line.startswith('Serial number') and not card_serial:
    #        card_serial = line.split(':', 1)[-1].strip()

    #if card_name and card_serial:
    card_keys = subprocess.check_output(['ssh-add', '-L'],
        stderr=subprocess.PIPE)
    card_keys = card_keys.decode('utf-8')
    for line in card_keys.splitlines():
        if 'cardno:' in line:
            card_serial = line.split('cardno:', 1)[-1].split()[0].strip()
            if card_serial:
                if len(card_serial) > 6:
                    card_serial = card_serial[4:]
                card_name = 'Smart Card'
                card_pub_key = line.strip()
                break
except:
    pass

if platform.system() == 'Darwin':
    try:
        subprocess.check_call(
            ['gpg-connect-agent', 'updatestartuptty', '/bye'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except:
        pass

if conf_ssh_card_serial:
    if not card_serial:
        print('ERROR: Missing Smart Card')
        print('If card is connected try running pritunl-ssh reset-gpg')
        sys.exit(1)

    if card_serial != conf_ssh_card_serial:
        print('ERROR: Incorrect Smart Card serial')
        print('Insert correct card, remove any other Smart Cards')
        sys.exit(1)

    if not card_pub_key:
        print('ERROR: Failed to load Smart Card public key')
        print('If device is configured, try running pritunl-ssh reset-gpg')
        sys.exit(1)

if not conf_zero_server:
    while True:
        server = input('Enter Pritunl Zero user hostname: ')
        if server:
            break
    server_url = urllib.parse.urlparse(server)
    conf_zero_server = 'https://%s' % (server_url.netloc or server_url.path)
    changed = True

print('SERVER: ' + conf_zero_server)

ask_register_card = False
if not conf_ssh_card_serial and (not conf_pub_key_path or
        not os.path.exists(os.path.expanduser(conf_pub_key_path))):
    ssh_names = []

    if card_name and card_serial:
        ssh_names.append('%s (%s)' % (card_name, card_serial))

    if os.path.exists(ssh_dir_path):
        for filename in os.listdir(ssh_dir_path):
            if '.pub' not in filename or '-cert.pub' in filename:
                continue
            ssh_names.append(filename)

    if not len(ssh_names):
        print('ERROR: No SSH keys found, run "ssh-keygen -t ed25519" ' +
            'to create a key')
        sys.exit(1)

    print('Select SSH key or device:')

    for i, ssh_name in enumerate(ssh_names):
        print('[%d] %s' % (i+1, ssh_name))

    while True:
        key_input = input('Enter number or full path to key: ')
        if key_input:
            break

    try:
        index = int(key_input) - 1

        if card_name and card_serial and index == 0:
            conf_ssh_card_serial = card_serial
        else:
            conf_pub_key_path = os.path.join(SSH_DIR, ssh_names[index])
    except (ValueError, IndexError):
        pass

    if not conf_pub_key_path and not conf_ssh_card_serial:
        if key_input in ssh_names:
            conf_pub_key_path = os.path.join(SSH_DIR, key_input)
        else:
            conf_pub_key_path = key_input

    if conf_ssh_card_serial:
        conf_pub_key_path = None
        ask_register_card = True
    else:
        conf_ssh_card_serial = None
        conf_pub_key_path = os.path.normpath(conf_pub_key_path)
    changed = True

bash_profile_path_full = os.path.expanduser(BASH_PROFILE_PATH)

ssh_config_path = conf_ssh_config_path or DEF_SSH_CONF_PATH
ssh_config_path_full = os.path.expanduser(ssh_config_path)

known_hosts_path = conf_known_hosts_path or DEF_KNOWN_HOSTS_PATH
known_hosts_path_full = os.path.expanduser(known_hosts_path)

if conf_ssh_card_serial:
    base_cert_path = SSH_DIR + '/pritunl-cert.pub'
    base_cert_path_full = os.path.expanduser(base_cert_path)
else:
    base_cert_path = conf_pub_key_path.rsplit('.pub', 1)[0] + '-cert.pub'
    base_cert_path_full = os.path.expanduser(base_cert_path)

if conf_ssh_card_serial:
    print('SSH_DEVICE: ' + conf_ssh_card_serial)
    pub_key_path_full = None
else:
    pub_key_path_full = os.path.expanduser(conf_pub_key_path)

    if not os.path.exists(pub_key_path_full):
        print('ERROR: Selected SSH key does not exist')
        sys.exit(1)

    if not pub_key_path_full.endswith('.pub'):
        print('ERROR: SSH key path must end with .pub')
        sys.exit(1)

    print('SSH_KEY: ' + conf_pub_key_path)

if '--port-forward' in sys.argv[1:] or 'port-forward' in sys.argv[1:]:
    ports = sys.argv[-1].split(':')

    try:
        subprocess.check_call([
            'ssh',
            '-N', '-L',
            '%s:localhost:%s' % (ports[0], ports[1]),
            sys.argv[-2]],
            # stdout=subprocess.PIPE,
            # stderr=subprocess.PIPE,
        )
    except KeyboardInterrupt:
        sys.exit(0)

    sys.exit(0)

if '--alias' in sys.argv[1:] or 'alias' in sys.argv[1:]:
    bash_profile_modified = False
    bash_profile_data = ''

    if os.path.exists(bash_profile_path_full):
        with open(bash_profile_path_full, 'r') as known_file:
            for line in known_file.readlines():
                if line.strip().endswith('# pritunl-zero'):
                    bash_profile_modified = True
                    continue
                bash_profile_data += line

    if bash_profile_data and not bash_profile_data.endswith('\n\n'):
        if bash_profile_data.endswith('\n'):
            bash_profile_data += '\n'
        else:
            bash_profile_data += '\n\n'

    ssh_input = input(
        'Enable ssh alias to autorun pritunl-ssh? [Y/n]: ')
    if not ssh_input.lower().startswith('n'):
        bash_profile_modified = True
        bash_profile_data += 'alias ssh="pritunl-ssh; ssh" # pritunl-zero\n'

    if bash_profile_modified:
        print('BASH_PROFILE: ' + BASH_PROFILE_PATH)
        with open(bash_profile_path_full, 'w') as bash_profile_file:
            bash_profile_file.write(bash_profile_data)

        print('Bash profile configured open new shell or run ' +
            '"source %s" to update environment' % BASH_PROFILE_PATH)

    sys.exit(0)

if '--clear-strict-host' in sys.argv[1:] or \
        'clear-strict-host' in sys.argv[1:]:
    if os.path.exists(base_cert_path_full):
        os.remove(base_cert_path_full)
    for i in range(100):
        num_cert_path = base_cert_path_full.replace('.pub', '%02d.pub' % i)
        if os.path.exists(num_cert_path):
            os.remove(num_cert_path)
        else:
            break

    known_hosts_modified = False
    known_hosts_data = ''

    if os.path.exists(known_hosts_path_full):
        with open(known_hosts_path_full, 'r') as known_file:
            for line in known_file.readlines():
                if line.strip().endswith('# pritunl-zero'):
                    known_hosts_modified = True
                    continue
                known_hosts_data += line

    if known_hosts_modified:
        print('KNOWN_HOSTS: ' + known_hosts_path)
        with open(known_hosts_path_full, 'w') as known_file:
            os.chmod(known_hosts_path_full, 0o600)
            known_file.write(known_hosts_data)

    ssh_config_modified = False
    ssh_config_data = ''
    ssh_config_temp = None

    if os.path.exists(ssh_config_path_full):
        host_skip = 0
        with open(ssh_config_path_full, 'r') as config_file:
            for line in config_file.readlines() + ['\n']:
                if host_skip:
                    if host_skip > 1 and not line.startswith('	'):
                        host_skip = 0
                        if len(ssh_config_temp) > 2:
                            ssh_config_data += ''.join(ssh_config_temp)
                        ssh_config_temp = None
                    else:
                        host_skip += 1
                        if 'StrictHostKeyChecking ' not in line:
                            ssh_config_temp.append(line)
                        continue
                if line.startswith('# pritunl-zero'):
                    ssh_config_modified = True
                    host_skip = 1
                    ssh_config_temp = [line]
                    continue
                ssh_config_data += line

    ssh_config_data = ssh_config_data[:-1]

    if ssh_config_modified:
        print('SSH_CONFIG: ' + ssh_config_path)
        with open(ssh_config_path_full, 'w') as config_file:
            os.chmod(ssh_config_path_full, 0o600)
            config_file.write(ssh_config_data)

    print('Successfully cleared strict host checking configuration')
    sys.exit(0)

if '--clear-bastion-host' in sys.argv[1:] or \
        'clear-bastion-host' in sys.argv[1:]:
    if os.path.exists(base_cert_path_full):
        os.remove(base_cert_path_full)
    for i in range(100):
        num_cert_path = base_cert_path_full.replace('.pub', '%02d.pub' % i)
        if os.path.exists(num_cert_path):
            os.remove(num_cert_path)
        else:
            break

    known_hosts_modified = False
    known_hosts_data = ''

    if os.path.exists(known_hosts_path_full):
        with open(known_hosts_path_full, 'r') as known_file:
            for line in known_file.readlines():
                if line.strip().endswith('# pritunl-zero'):
                    known_hosts_modified = True
                    continue
                known_hosts_data += line

    if known_hosts_modified:
        print('KNOWN_HOSTS: ' + known_hosts_path)
        with open(known_hosts_path_full, 'w') as known_file:
            os.chmod(known_hosts_path_full, 0o600)
            known_file.write(known_hosts_data)

    ssh_config_modified = False
    ssh_config_data = ''
    ssh_config_temp = None

    if os.path.exists(ssh_config_path_full):
        host_skip = 0
        with open(ssh_config_path_full, 'r') as config_file:
            for line in config_file.readlines() + ['\n']:
                if host_skip:
                    if host_skip > 1 and not line.startswith('	'):
                        host_skip = 0
                        if len(ssh_config_temp) > 2:
                            ssh_config_data += ''.join(ssh_config_temp)
                        ssh_config_temp = None
                    else:
                        host_skip += 1
                        if 'ProxyJump ' not in line:
                            ssh_config_temp.append(line)
                        continue
                if line.startswith('# pritunl-zero'):
                    ssh_config_modified = True
                    host_skip = 1
                    ssh_config_temp = [line]
                    continue
                ssh_config_data += line

    ssh_config_data = ssh_config_data[:-1]

    if ssh_config_modified:
        print('SSH_CONFIG: ' + ssh_config_path)
        with open(ssh_config_path_full, 'w') as config_file:
            os.chmod(ssh_config_path_full, 0o600)
            config_file.write(ssh_config_data)

    print('Successfully cleared bastion host configuration')
    sys.exit(0)

if '--clear' in sys.argv[1:] or 'clear' in sys.argv[1:]:
    if os.path.exists(base_cert_path_full):
        os.remove(base_cert_path_full)
    for i in range(100):
        num_cert_path = base_cert_path_full.replace('.pub', '%02d.pub' % i)
        if os.path.exists(num_cert_path):
            os.remove(num_cert_path)
        else:
            break

    known_hosts_modified = False
    known_hosts_data = ''

    if os.path.exists(known_hosts_path_full):
        with open(known_hosts_path_full, 'r') as known_file:
            for line in known_file.readlines():
                if line.strip().endswith('# pritunl-zero'):
                    known_hosts_modified = True
                    continue
                known_hosts_data += line

    if known_hosts_modified:
        print('KNOWN_HOSTS: ' + known_hosts_path)
        with open(known_hosts_path_full, 'w') as known_file:
            os.chmod(known_hosts_path_full, 0o600)
            known_file.write(known_hosts_data)

    ssh_config_modified = False
    ssh_config_data = ''

    if os.path.exists(ssh_config_path_full):
        host_skip = 0
        with open(ssh_config_path_full, 'r') as config_file:
            for line in config_file.readlines() + ['\n']:
                if host_skip:
                    if host_skip > 1 and not line.startswith('	'):
                        host_skip = 0
                    else:
                        host_skip += 1
                        continue
                if line.startswith('# pritunl-zero'):
                    ssh_config_modified = True
                    host_skip = 1
                    continue
                ssh_config_data += line

    ssh_config_data = ssh_config_data[:-1]

    if ssh_config_modified:
        print('SSH_CONFIG: ' + ssh_config_path)
        with open(ssh_config_path_full, 'w') as config_file:
            os.chmod(ssh_config_path_full, 0o600)
            config_file.write(ssh_config_data)

    print('Successfully cleared SSH configuration')
    sys.exit(0)

if '--info' in sys.argv[1:] or 'info' in sys.argv[1:]:
    found = False
    if os.path.exists(base_cert_path_full):
        found = True
        subprocess.check_call(['ssh-keygen', '-L', '-f', base_cert_path_full])
        sys.exit(0)
    else:
        for i in range(100):
            num_cert_path = base_cert_path_full.replace(
                '.pub', '%02d.pub' % i)
            if os.path.exists(num_cert_path):
                found = True
                subprocess.check_call(
                    ['ssh-keygen', '-L', '-f', num_cert_path])
            else:
                break

    if found:
        sys.exit(0)
    else:
        print('ERROR: No SSH certificates available')
        sys.exit(1)

with open(conf_path, 'w') as conf_file:
    os.chmod(conf_path, 0o600)
    conf_file.write(json.dumps({
        'server': conf_zero_server,
        'public_key_path': conf_pub_key_path,
        'known_hosts_path': conf_known_hosts_path,
        'ssh_config_path': conf_ssh_config_path,
        'ssh_card_serial': conf_ssh_card_serial,
    }))

register_card = False
if ask_register_card:
    register_input = input('Register Smart Card? [Y/n]: ')
    register_card = not register_input.lower().startswith('n')

if '--register-smart-card' in sys.argv[1:] or \
        'register-smart-card' in sys.argv[1:] or register_card:
    device_key = base64.urlsafe_b64encode(
        card_pub_key.encode()).decode('utf-8')
    device_url = conf_zero_server + '/ssh?device=' + device_key

    open_browser(device_url)
    exit(0)

def check_cert_valid(cert_path):
    cur_date = datetime.datetime.now() + datetime.timedelta(
        seconds=30)

    status = subprocess.check_output(
        ['ssh-keygen', '-L', '-f', cert_path])
    status = status.decode('utf-8')

    cert_valid = True
    for line in status.splitlines():
        line = line.strip()
        if line.startswith('Valid:'):
            line = line.split('to')[-1].strip()
            valid_to = datetime.datetime.strptime(
                line, '%Y-%m-%dT%H:%M:%S')

            if cur_date >= valid_to:
                cert_valid = False
                break

    return cert_valid

cert_valid = False
if '--renew' not in sys.argv[1:] and 'renew' not in sys.argv[1:]:
    try:
        if os.path.exists(base_cert_path_full):
            cert_valid = check_cert_valid(base_cert_path_full)
        else:
            cert_valid = False
            for i in range(100):
                num_cert_path = base_cert_path_full.replace(
                    '.pub', '%02d.pub' % i)
                if os.path.exists(num_cert_path):
                    if check_cert_valid(num_cert_path):
                        cert_valid = True
                    else:
                        cert_valid = False
                        break
                else:
                    break
    except Exception as exception:
        print('WARN: Failed to get certificate expiration')
        print(str(exception))

if cert_valid:
    print('Certificate has not expired')
    sys.exit(0)

if conf_ssh_card_serial:
    pub_key_data = card_pub_key
else:
    with open(pub_key_path_full, 'r') as pub_key_file:
        pub_key_data = pub_key_file.read().strip()

req = urllib.request.Request(
    conf_zero_server + '/ssh/challenge',
    data=json.dumps({
        'public_key': pub_key_data,
    }).encode(),
)
req.add_header('Content-Type', 'application/json')
req.get_method = lambda: 'POST'
resp_data = ''
resp_error = None
status_code = None
try:
    resp = urllib.request.urlopen(req)
    resp_data = resp.read().decode('utf-8')
    status_code = resp.getcode()
except urllib.error.HTTPError as exception:
    status_code = exception.code
    try:
        resp_data = exception.read()
        resp_error = str(json.loads(resp_data)['error_msg'])
    except:
        pass

if status_code != 200:
    if resp_error:
        print('ERROR: ' + resp_error)
    else:
        print('ERROR: SSH challenge request failed with status %d' % \
            status_code)
        if resp_data:
            print(resp_data.strip())
    sys.exit(1)

token = json.loads(resp_data)['token']

token_url = conf_zero_server + '/ssh?ssh-token=' + token
open_browser(token_url)

for _ in range(10):
    req = urllib.request.Request(
        conf_zero_server + '/ssh/challenge',
        data=json.dumps({
            'public_key': pub_key_data,
            'token': token,
        }).encode(),
    )
    req.add_header('Content-Type', 'application/json')
    req.get_method = lambda: 'PUT'
    resp_data = ''
    resp_error = None
    status_code = None
    try:
        resp = urllib.request.urlopen(req)
        status_code = resp.getcode()
        resp_data = resp.read().decode('utf-8')
    except urllib.error.HTTPError as exception:
        status_code = exception.code
        try:
            resp_data = exception.read().decode('utf-8')
            resp_error = str(json.loads(resp_data)['error_msg'])
        except:
            pass

    if status_code == 205:
        continue
    break

if status_code == 205:
    print('ERROR: SSH verification request timed out')
    sys.exit(1)

elif status_code == 401:
    print('ERROR: SSH verification request was denied')
    sys.exit(1)

elif status_code == 404:
    print('ERROR: SSH verification request has expired')
    sys.exit(1)

elif status_code != 200:
    if resp_error:
        print('ERROR: ' + resp_error)
    else:
        print('ERROR: SSH verification failed with status %d' % status_code)
        if resp_data:
            print(resp_data.strip())
    sys.exit(1)

cert_data = json.loads(resp_data)
certificates = cert_data['certificates']
cert_authorities = cert_data.get('certificate_authorities')
cert_hosts = cert_data.get('hosts')

if os.path.exists(base_cert_path_full):
    os.remove(base_cert_path_full)
for i in range(100):
    num_cert_path = base_cert_path_full.replace('.pub', '%02d.pub' % i)
    if os.path.exists(num_cert_path):
        os.remove(num_cert_path)
    else:
        break

if len(certificates) < 2:
    with open(base_cert_path_full, 'w') as cert_file:
        os.chmod(base_cert_path_full, 0o600)
        cert_file.write('\n'.join(certificates) + '\n')
    print('CERTIFICATE: ' + base_cert_path)
else:
    for i, certificate in enumerate(certificates):
        num_cert_path = base_cert_path_full.replace('.pub', '%02d.pub' % i)
        with open(num_cert_path, 'w') as cert_file:
            os.chmod(num_cert_path, 0o600)
            cert_file.write(certificate + '\n')
        print('CERTIFICATE: ' + base_cert_path.replace(
            '.pub', '%02d.pub' % i))

known_hosts_modified = False
known_hosts_data = ''

for cert_authority in cert_authorities or []:
    known_hosts_modified = True
    known_hosts_data += cert_authority + ' # pritunl-zero\n'

if os.path.exists(known_hosts_path_full):
    with open(known_hosts_path_full, 'r') as known_file:
        for line in known_file.readlines():
            if line.strip().endswith('# pritunl-zero'):
                known_hosts_modified = True
                continue
            known_hosts_data += line

if known_hosts_modified:
    print('KNOWN_HOSTS: ' + known_hosts_path)
    with open(known_hosts_path_full, 'w') as known_file:
        os.chmod(known_hosts_path_full, 0o600)
        known_file.write(known_hosts_data)

ssh_config_modified = False
ssh_config_data = ''

if os.path.exists(ssh_config_path_full):
    host_skip = 0
    with open(ssh_config_path_full, 'r') as config_file:
        for line in config_file.readlines() + ['\n']:
            if host_skip:
                if line.startswith('CertificateFile'):
                    host_skip = 0
                    continue
                elif host_skip > 1 and not line.startswith('	'):
                    host_skip = 0
                else:
                    host_skip += 1
                    continue
            if line.startswith('# pritunl-zero'):
                ssh_config_modified = True
                host_skip = 1
                continue
            ssh_config_data += line

ssh_config_data = ssh_config_data[:-1]

if ssh_config_data and not ssh_config_data.endswith('\n\n'):
    if ssh_config_data.endswith('\n'):
        ssh_config_data += '\n'
    else:
        ssh_config_data += '\n\n'

if conf_ssh_card_serial or len(certificates):
    ssh_config_modified = True

    if len(certificates) < 2:
        ssh_config_data += '# pritunl-zero\nCertificateFile %s\n' % \
            base_cert_path
    else:
        for i in range(len(certificates)):
            num_cert_path = base_cert_path.replace('.pub', '%02d.pub' % i)
            ssh_config_data += '# pritunl-zero\nCertificateFile %s\n' % \
                num_cert_path

for cert_host in cert_hosts or []:
    if cert_host['strict_host_checking'] or cert_host['proxy_host']:
        ssh_config_modified = True

        matches = []
        if cert_host.get('matches'):
            matches = cert_host.get('matches')
        elif cert_host['domain']:
            matches = [cert_host['domain']]

        for match in matches:
            ssh_config_data += '# pritunl-zero\nHost %s\n' % match

            if cert_host['strict_host_checking']:
                ssh_config_data += '	StrictHostKeyChecking yes\n'

            if cert_host['proxy_host']:
                ssh_config_data += '	ProxyJump %s\n' % \
                    cert_host['proxy_host']

        if cert_host['proxy_host'] and (cert_host['strict_host_checking'] or
                cert_host.get('strict_bastion_checking')):
            ssh_config_data += '# pritunl-zero\nHost %s\n' % \
                cert_host['proxy_host'].split('@', 1)[-1].split(':', 1)[0]
            ssh_config_data += '	StrictHostKeyChecking yes\n'

if ssh_config_modified:
    print('SSH_CONFIG: ' + ssh_config_path)
    with open(ssh_config_path_full, 'w') as config_file:
        os.chmod(ssh_config_path_full, 0o600)
        config_file.write(ssh_config_data)

print('Successfully validated SSH key')
