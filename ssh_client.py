#!/usr/bin/env python
import os
import json
import urllib
import urllib2
import subprocess
import urlparse
import sys
import datetime

VERSION = '1.0.765.26'
SSH_DIR = '~/.ssh'
CONF_PATH = SSH_DIR + '/pritunl-zero.json'
DEF_KNOWN_HOSTS_PATH = '~/.ssh/known_hosts'
DEF_SSH_CONF_PATH = '~/.ssh/config'

USAGE = """\
Usage: pritunl-ssh [command]

Commands:
  help                Show help
  version             Print the version and exit
  config              Reconfigure options
  keybase             Configure keybase
  info                Show current certificate information
  renew               Force certificate renewal
  clear               Remove all configuration changes made by Pritunl
  clear-strict-host   Remove strict host checking configuration changes
  clear-bastion-host  Remove bastion host configuration changes"""

conf_zero_server = None
conf_pub_key_path = None
conf_keybase_state = None
conf_known_hosts_path = None
conf_ssh_config_path = None
keybase_username = None
ssh_dir_path = os.path.expanduser(SSH_DIR)
conf_path = os.path.expanduser(CONF_PATH)
changed = False

try:
    keybase_status = subprocess.check_output(
        ["keybase", "status", "--json"],
        stderr=subprocess.PIPE,
    )
    keybase_data = json.loads(keybase_status)
    keybase_username = keybase_data['Username']
except:
    pass

if '--help' in sys.argv[1:] or 'help' in sys.argv[1:]:
    print USAGE
    sys.exit(0)

if '--version' in sys.argv[1:] or 'version' in sys.argv[1:]:
    print 'pritunl-ssh v' + VERSION
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
            conf_keybase_state = conf_data.get('keybase_state')
            conf_known_hosts_path = conf_data.get('known_hosts_path')
            conf_ssh_config_path = conf_data.get('ssh_config_path')
        except:
            print 'WARNING: Failed to parse config file'

if not conf_zero_server:
    while True:
        server = raw_input('Enter Pritunl Zero user hostname: ')
        if server:
            break
    server_url = urlparse.urlparse(server)
    conf_zero_server = 'https://%s' % (server_url.netloc or server_url.path)
    changed = True

print 'SERVER: ' + conf_zero_server

if not conf_pub_key_path or not os.path.exists(
        os.path.expanduser(conf_pub_key_path)):
    if not os.path.exists(ssh_dir_path):
        print 'ERROR: No SSH keys found, run "ssh-keygen" to create a key'
        sys.exit(0)

    ssh_names = []

    print 'Select SSH key:'

    for filename in os.listdir(ssh_dir_path):
        if '.pub' not in filename or '-cert.pub' in filename:
            continue

        ssh_names.append(filename)
        print '[%d] %s' % (len(ssh_names), filename)

    while True:
        key_input = raw_input('Enter key number or full path to key: ')
        if key_input:
            break

    try:
        index = int(key_input)
        conf_pub_key_path = os.path.join(SSH_DIR, ssh_names[index - 1])
    except ValueError, IndexError:
        pass

    if not conf_pub_key_path:
        if key_input in ssh_names:
            conf_pub_key_path = os.path.join(SSH_DIR, key_input)
        else:
            conf_pub_key_path = key_input

    conf_pub_key_path = os.path.normpath(conf_pub_key_path)
    changed = True

ssh_config_path = conf_ssh_config_path or DEF_SSH_CONF_PATH
ssh_config_path_full = os.path.expanduser(ssh_config_path)

known_hosts_path = conf_known_hosts_path or DEF_KNOWN_HOSTS_PATH
known_hosts_path_full = os.path.expanduser(known_hosts_path)

cert_path = conf_pub_key_path.rsplit('.pub', 1)[0] + '-cert.pub'
cert_path_full = os.path.expanduser(cert_path)

pub_key_path_full = os.path.expanduser(conf_pub_key_path)

if not os.path.exists(pub_key_path_full):
    print 'ERROR: Selected SSH key does not exist'
    sys.exit(0)

if not pub_key_path_full.endswith('.pub'):
    print 'ERROR: SSH key path must end with .pub'
    sys.exit(0)

print 'SSH_KEY: ' + conf_pub_key_path

if '--clear-strict-host' in sys.argv[1:] or \
        'clear-strict-host' in sys.argv[1:]:
    if os.path.exists(cert_path_full):
        os.remove(cert_path_full)

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
        print 'KNOWN_HOSTS: ' + known_hosts_path
        with open(known_hosts_path_full, 'w') as known_file:
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
        print 'SSH_CONFIG: ' + ssh_config_path
        with open(ssh_config_path_full, 'w') as config_file:
            config_file.write(ssh_config_data)

    print 'Successfully cleared strict host checking configuration'
    sys.exit(0)

if '--clear-bastion-host' in sys.argv[1:] or \
        'clear-bastion-host' in sys.argv[1:]:
    if os.path.exists(cert_path_full):
        os.remove(cert_path_full)

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
        print 'KNOWN_HOSTS: ' + known_hosts_path
        with open(known_hosts_path_full, 'w') as known_file:
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
        print 'SSH_CONFIG: ' + ssh_config_path
        with open(ssh_config_path_full, 'w') as config_file:
            config_file.write(ssh_config_data)

    print 'Successfully cleared bastion host configuration'
    sys.exit(0)

if '--clear' in sys.argv[1:] or 'clear' in sys.argv[1:]:
    if os.path.exists(cert_path_full):
        os.remove(cert_path_full)

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
        print 'KNOWN_HOSTS: ' + known_hosts_path
        with open(known_hosts_path_full, 'w') as known_file:
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
        print 'SSH_CONFIG: ' + ssh_config_path
        with open(ssh_config_path_full, 'w') as config_file:
            config_file.write(ssh_config_data)

    print 'Successfully cleared SSH configuration'
    sys.exit(0)

if '--info' in sys.argv[1:] or 'info' in sys.argv[1:]:
    if not os.path.exists(cert_path_full):
        print 'ERROR: No SSH certificates available'
        sys.exit(0)
    subprocess.check_call(['ssh-keygen', '-L', '-f', cert_path_full])
    sys.exit(0)

keybase_associate = False
keybase_exit = False
if '--keybase' in sys.argv[1:] or 'keybase' in sys.argv[1:]:
    if not keybase_username:
        print 'ERROR: Unable to read keybase status'
        sys.exit(0)
    conf_keybase_state = None
    keybase_exit = True

if keybase_username and conf_keybase_state is None:
    keybase_input = raw_input('Authenticate with Keybase? [Y/n]: ')
    if not keybase_input.startswith('n'):
        keybase_associate = True
    else:
        conf_keybase_state = False

if keybase_associate:
    req = urllib2.Request(
        conf_zero_server + '/keybase/associate',
        data=json.dumps({
            'username': keybase_username,
        }),
    )
    req.add_header('Content-Type', 'application/json')
    req.get_method = lambda: 'POST'
    resp_data = ''
    resp_error = None
    status_code = None
    try:
        resp = urllib2.urlopen(req)
        resp_data = resp.read()
        status_code = resp.getcode()
    except urllib2.HTTPError as exception:
        status_code = exception.code
        try:
            resp_data = exception.read()
            resp_error = str(json.loads(resp_data)['error_msg'])
        except:
            pass

    if status_code != 200:
        if resp_error:
            print 'ERROR: ' + resp_error
        else:
            print 'ERROR: Keybase association failed with status %d' % \
                status_code
            if resp_data:
                print resp_data.strip()
        sys.exit(0)

    token = json.loads(resp_data)['token']
    message = json.loads(resp_data)['message']

    signature = subprocess.check_output(
        ["keybase", "sign", "--message", message],
    ).strip()

    req = urllib2.Request(
        conf_zero_server + '/keybase/check',
        data=json.dumps({
            'token': token,
            'signature': signature,
        }),
    )
    req.add_header('Content-Type', 'application/json')
    req.get_method = lambda: 'PUT'
    resp_data = ''
    resp_error = None
    status_code = None
    try:
        resp = urllib2.urlopen(req)
        resp_data = resp.read()
        status_code = resp.getcode()
    except urllib2.HTTPError as exception:
        status_code = exception.code
        try:
            resp_data = exception.read()
            resp_error = str(json.loads(resp_data)['error_msg'])
        except:
            pass

    if status_code != 200 and status_code != 404:
        if resp_error:
            print 'ERROR: ' + resp_error
        else:
            print 'ERROR: Keybase check failed with status %d' % status_code
            if resp_data:
                print resp_data.strip()
        sys.exit(0)

    if status_code == 404:
        token_url = conf_zero_server + '/keybase?' + urllib.urlencode({
            'keybase-token': token,
            'keybase-sig': signature,
        })

        print 'OPEN: ' + token_url

        try:
            subprocess.Popen(
                ['xdg-open', token_url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                subprocess.Popen(['open', token_url])
            except:
                pass

        for _ in xrange(10):
            req = urllib2.Request(
                conf_zero_server + '/keybase/associate/' + token,
            )
            req.get_method = lambda: 'GET'
            resp_data = ''
            resp_error = None
            status_code = None
            try:
                resp = urllib2.urlopen(req)
                status_code = resp.getcode()
                resp_data = resp.read()
            except urllib2.HTTPError as exception:
                status_code = exception.code
                try:
                    resp_data = exception.read()
                    resp_error = str(json.loads(resp_data)['error_msg'])
                except:
                    pass

            if status_code == 205:
                continue
            break

        if status_code == 205:
            print 'ERROR: Keybase association request timed out'
            sys.exit(0)

        if status_code == 401:
            print 'ERROR: Keybase association request was denied'
            sys.exit(0)

        if status_code == 404:
            print 'ERROR: Keybase association request has expired'
            sys.exit(0)

        if status_code != 200:
            if resp_error:
                print 'ERROR: ' + resp_error
            else:
                print 'ERROR: Keybase association failed with status %d' % \
                    status_code
                if resp_data:
                    print resp_data.strip()
            sys.exit(0)

    conf_keybase_state = True

with open(conf_path, 'w') as conf_file:
    conf_file.write(json.dumps({
        'server': conf_zero_server,
        'public_key_path': conf_pub_key_path,
        'keybase_state': conf_keybase_state,
        'known_hosts_path': conf_known_hosts_path,
        'ssh_config_path': conf_ssh_config_path,
    }))

if keybase_username and conf_keybase_state:
    print 'KEYBASE_USERNAME: ' + keybase_username

if keybase_exit:
    sys.exit(0)

cert_valid = False
if '--renew' not in sys.argv[1:] and 'renew' not in sys.argv[1:]:
    try:
        if os.path.exists(cert_path_full):
            cur_date = datetime.datetime.now() + datetime.timedelta(seconds=30)

            status = subprocess.check_output(
                ['ssh-keygen', '-L', '-f', cert_path_full])

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
    except Exception as exception:
        print 'WARN: Failed to get certificate expiration'
        print str(exception)

if cert_valid:
    print 'Certificate has not expired'
    sys.exit(0)

with open(pub_key_path_full, 'r') as pub_key_file:
    pub_key_data = pub_key_file.read().strip()

if conf_keybase_state:
    req = urllib2.Request(
        conf_zero_server + '/keybase/challenge',
        data=json.dumps({
            'username': keybase_username,
            'public_key': pub_key_data,
        }),
    )
    req.add_header('Content-Type', 'application/json')
    req.get_method = lambda: 'POST'
    resp_data = ''
    resp_error = None
    status_code = None
    try:
        resp = urllib2.urlopen(req)
        resp_data = resp.read()
        status_code = resp.getcode()
    except urllib2.HTTPError as exception:
        status_code = exception.code
        try:
            resp_data = exception.read()
            resp_error = str(json.loads(resp_data)['error_msg'])
        except:
            pass

    if status_code != 200:
        if resp_error:
            print 'ERROR: ' + resp_error
        else:
            print 'ERROR: Keybase challenge failed with status %d' % \
                status_code
            if resp_data:
                print resp_data.strip()
        sys.exit(0)

    token = json.loads(resp_data)['token']
    message = json.loads(resp_data)['message']

    signature = subprocess.check_output(
        ["keybase", "sign", "--message", message],
    ).strip()
    keybase_data = json.loads(keybase_status)

    req = urllib2.Request(
        conf_zero_server + '/keybase/challenge',
        data=json.dumps({
            'token': token,
            'signature': signature,
        }),
    )
    req.add_header('Content-Type', 'application/json')
    req.get_method = lambda: 'PUT'
    resp_data = ''
    resp_error = None
    status_code = None
    try:
        resp = urllib2.urlopen(req)
        resp_data = resp.read()
        status_code = resp.getcode()
    except urllib2.HTTPError as exception:
        status_code = exception.code
        try:
            resp_data = exception.read()
            resp_error = str(json.loads(resp_data)['error_msg'])
        except:
            pass

    if status_code == 404:
        print 'ERROR: Keybase challenge request has expired'
        sys.exit(0)

    if status_code != 200:
        if resp_error:
            print 'ERROR: ' + resp_error
        else:
            print 'ERROR: Keybase challenge failed with status %d' % \
                status_code
            if resp_data:
                print resp_data.strip()
        sys.exit(0)

    certificates = json.loads(resp_data)['certificates']

    with open(cert_path_full, 'w') as cert_file:
        cert_file.write('\n'.join(certificates) + '\n')

    print 'CERTIFICATE: ' + cert_path
    print 'Successfully validated SSH key'

    sys.exit(0)

req = urllib2.Request(
    conf_zero_server + '/ssh/challenge',
    data=json.dumps({
        'public_key': pub_key_data,
    }),
)
req.add_header('Content-Type', 'application/json')
req.get_method = lambda: 'POST'
resp_data = ''
resp_error = None
status_code = None
try:
    resp = urllib2.urlopen(req)
    resp_data = resp.read()
    status_code = resp.getcode()
except urllib2.HTTPError as exception:
    status_code = exception.code
    try:
        resp_data = exception.read()
        resp_error = str(json.loads(resp_data)['error_msg'])
    except:
        pass

if status_code != 200:
    if resp_error:
        print 'ERROR: ' + resp_error
    else:
        print 'ERROR: SSH challenge request failed with status %d' % \
            status_code
        if resp_data:
            print resp_data.strip()
    sys.exit(0)

token = json.loads(resp_data)['token']

token_url = conf_zero_server + '/ssh?ssh-token=' + token

print 'OPEN: ' + token_url

try:
    subprocess.Popen(
        ['xdg-open', token_url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
except:
    try:
        subprocess.Popen(['open', token_url])
    except:
        pass

for _ in xrange(10):
    req = urllib2.Request(
        conf_zero_server + '/ssh/challenge',
        data=json.dumps({
            'public_key': pub_key_data,
            'token': token,
        }),
    )
    req.add_header('Content-Type', 'application/json')
    req.get_method = lambda: 'PUT'
    resp_data = ''
    resp_error = None
    status_code = None
    try:
        resp = urllib2.urlopen(req)
        status_code = resp.getcode()
        resp_data = resp.read()
    except urllib2.HTTPError as exception:
        status_code = exception.code
        try:
            resp_data = exception.read()
            resp_error = str(json.loads(resp_data)['error_msg'])
        except:
            pass

    if status_code == 205:
        continue
    break

if status_code == 205:
    print 'ERROR: SSH verification request timed out'
    sys.exit(0)

if status_code == 401:
    print 'ERROR: SSH verification request was denied'
    sys.exit(0)

if status_code == 404:
    print 'ERROR: SSH verification request has expired'
    sys.exit(0)

if status_code != 200:
    if resp_error:
        print 'ERROR: ' + resp_error
    else:
        print 'ERROR: SSH verification failed with status %d' % status_code
        if resp_data:
            print resp_data.strip()
    sys.exit(0)

cert_data = json.loads(resp_data)
certificates = cert_data['certificates']
cert_authorities = cert_data.get('certificate_authorities')
cert_hosts = cert_data.get('hosts')

with open(cert_path_full, 'w') as cert_file:
    cert_file.write('\n'.join(certificates) + '\n')

print 'CERTIFICATE: ' + cert_path

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
    print 'KNOWN_HOSTS: ' + known_hosts_path
    with open(known_hosts_path_full, 'w') as known_file:
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

if ssh_config_data and not ssh_config_data.endswith('\n\n'):
    if ssh_config_data.endswith('\n'):
        ssh_config_data += '\n'
    else:
        ssh_config_data += '\n\n'

for cert_host in cert_hosts or []:
    ssh_config_modified = True
    ssh_config_data += '# pritunl-zero\nHost %s\n' % cert_host['domain']

    if cert_host['strict_host_checking']:
        ssh_config_data += '	StrictHostKeyChecking yes\n'

    if cert_host['proxy_host']:
        ssh_config_data += '	ProxyJump %s\n' % cert_host['proxy_host']

    if cert_host['proxy_host'] and cert_host['strict_host_checking']:
        ssh_config_data += '# pritunl-zero\nHost %s\n' % \
            cert_host['proxy_host'].split('@', 1)[-1]
        ssh_config_data += '	StrictHostKeyChecking yes\n'

if ssh_config_modified:
    print 'SSH_CONFIG: ' + ssh_config_path
    with open(ssh_config_path_full, 'w') as config_file:
        config_file.write(ssh_config_data)

print 'Successfully validated SSH key'
