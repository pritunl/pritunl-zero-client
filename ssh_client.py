#!/usr/bin/env python
import os
import json
import urllib
import urllib2
import subprocess
import urlparse
import sys
import datetime

VERSION = '1.0.754.23'
SSH_DIR = '~/.ssh'
CONF_PATH = SSH_DIR + '/pritunl-zero.json'

USAGE = """\
Usage: pritunl-ssh [command]

Commands:
  help      Show help
  version   Print the version and exit
  config    Reconfigure options
  keybase   Configure keybase
  info      Show current certificate information
  renew     Force certificate renewal"""

zero_server = None
pub_key_path = None
keybase_state = None
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
    exit()

if '--version' in sys.argv[1:] or 'version' in sys.argv[1:]:
    print 'pritunl-ssh v' + VERSION
    exit()

if '--config' not in sys.argv[1:] and \
        'config' not in sys.argv[1:] and \
    os.path.isfile(conf_path):
    with open(conf_path, 'r') as conf_file:
        conf_data = conf_file.read()
        try:
            conf_data = json.loads(conf_data)
            zero_server = conf_data.get('server')
            pub_key_path = conf_data.get('public_key_path')
            keybase_state = conf_data.get('keybase_state')
        except:
            print 'WARNING: Failed to parse config file'

if not zero_server:
    while True:
        server = raw_input('Enter Pritunl Zero user hostname: ')
        if server:
            break
    server_url = urlparse.urlparse(server)
    zero_server = 'https://%s' % (server_url.netloc or server_url.path)
    changed = True

print 'SERVER: ' + zero_server

if not pub_key_path or not os.path.exists(os.path.expanduser(pub_key_path)):
    if not os.path.exists(ssh_dir_path):
        print 'ERROR: No SSH keys found, run "ssh-keygen" to create a key'
        exit()

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
        pub_key_path = os.path.join(SSH_DIR, ssh_names[index - 1])
    except ValueError, IndexError:
        pass

    if not pub_key_path:
        if key_input in ssh_names:
            pub_key_path = os.path.join(SSH_DIR, key_input)
        else:
            pub_key_path = key_input

    pub_key_path = os.path.normpath(pub_key_path)
    changed = True

pub_key_path_full = os.path.expanduser(pub_key_path)
cert_path = pub_key_path.rsplit('.pub', 1)[0] + '-cert.pub'
cert_path_full = os.path.expanduser(cert_path)
if not os.path.exists(pub_key_path_full):
    print 'ERROR: Selected SSH key does not exist'
    exit()

if not pub_key_path_full.endswith('.pub'):
    print 'ERROR: SSH key path must end with .pub'
    exit()

print 'SSH_KEY: ' + pub_key_path

if '--info' in sys.argv[1:] or 'info' in sys.argv[1:]:
    if not os.path.exists(cert_path_full):
        print 'ERROR: No SSH certificates available'
        exit()
    subprocess.check_call(['ssh-keygen', '-L', '-f', cert_path_full])
    exit()

keybase_associate = False
keybase_exit = False
if '--keybase' in sys.argv[1:] or 'keybase' in sys.argv[1:]:
    if not keybase_username:
        print 'ERROR: Unable to read keybase status'
        exit()
    keybase_state = None
    keybase_exit = True

if keybase_username and keybase_state is None:
    keybase_input = raw_input('Authenticate with Keybase? [Y/n]: ')
    if not keybase_input.startswith('n'):
        keybase_associate = True
    else:
        keybase_state = False

if keybase_associate:
    req = urllib2.Request(
        zero_server + '/keybase/associate',
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
                print resp_data
        exit()

    token = json.loads(resp_data)['token']
    message = json.loads(resp_data)['message']

    signature = subprocess.check_output(
        ["keybase", "sign", "--message", message],
    ).strip()
    keybase_data = json.loads(keybase_status)

    req = urllib2.Request(
        zero_server + '/keybase/check',
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
                print resp_data
        exit()

    if status_code == 404:
        token_url = zero_server + '/keybase?' + urllib.urlencode({
            'keybase-token': token,
            'keybase-sig': signature,
        })

        print 'OPEN: ' + token_url

        try:
            subprocess.Popen(['open', token_url])
        except:
            pass

        for i in xrange(10):
            req = urllib2.Request(
                zero_server + '/keybase/associate/' + token,
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
            exit()

        if status_code == 401:
            print 'ERROR: Keybase association request was denied'
            exit()

        if status_code == 404:
            print 'ERROR: Keybase association request has expired'
            exit()

        if status_code != 200:
            if resp_error:
                print 'ERROR: ' + resp_error
            else:
                print 'ERROR: Keybase association failed with status %d' % \
                    status_code
                if resp_data:
                    print resp_data
            exit()

    keybase_state = True

with open(conf_path, 'w') as conf_file:
    conf_file.write(json.dumps({
        'server': zero_server,
        'public_key_path': pub_key_path,
        'keybase_state': keybase_state,
    }))

if keybase_username and keybase_state:
    print 'KEYBASE_USERNAME: ' + keybase_username

if keybase_exit:
    exit()

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
    exit()

with open(pub_key_path_full, 'r') as pub_key_file:
    pub_key_data = pub_key_file.read().strip()

if keybase_state:
    req = urllib2.Request(
        zero_server + '/keybase/challenge',
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
                print resp_data
        exit()

    token = json.loads(resp_data)['token']
    message = json.loads(resp_data)['message']

    signature = subprocess.check_output(
        ["keybase", "sign", "--message", message],
    ).strip()
    keybase_data = json.loads(keybase_status)

    req = urllib2.Request(
        zero_server + '/keybase/challenge',
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
        exit()

    if status_code != 200:
        if resp_error:
            print 'ERROR: ' + resp_error
        else:
            print 'ERROR: Keybase challenge failed with status %d' % \
                status_code
            if resp_data:
                print resp_data
        exit()

    certificates = json.loads(resp_data)['certificates']

    with open(cert_path_full, 'w') as cert_file:
        cert_file.write('\n'.join(certificates) + '\n')

    print 'CERTIFICATE: ' + cert_path
    print 'Successfully validated SSH key'

    exit()

req = urllib2.Request(
    zero_server + '/ssh/challenge',
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
            print resp_data
    exit()

token = json.loads(resp_data)['token']

token_url = zero_server + '/ssh?ssh-token=' + token

print 'OPEN: ' + token_url

try:
    subprocess.Popen(['open', token_url])
except:
    pass

for i in xrange(10):
    req = urllib2.Request(
        zero_server + '/ssh/challenge',
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
    exit()

if status_code == 401:
    print 'ERROR: SSH verification request was denied'
    exit()

if status_code == 404:
    print 'ERROR: SSH verification request has expired'
    exit()

if status_code == 412:
    print 'ERROR: SSH verification was approved but no ' \
        'certificates are available'
    exit()

if status_code != 200:
    if resp_error:
        print 'ERROR: ' + resp_error
    else:
        print 'ERROR: SSH verification failed with status %d' % status_code
        if resp_data:
            print resp_data
    exit()

certificates = json.loads(resp_data)['certificates']

with open(cert_path_full, 'w') as cert_file:
    cert_file.write('\n'.join(certificates) + '\n')

print 'CERTIFICATE: ' + cert_path
print 'Successfully validated SSH key'
