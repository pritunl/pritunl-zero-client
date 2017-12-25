#!/usr/bin/env python
import os
import json
import urllib2
import time
import urlparse
import sys
import datetime
import subprocess
import threading
import socket
import BaseHTTPServer

VERSION = '1.0.755.26'
CONF_PATH = '/etc/pritunl-ssh-host.json'
DEF_SSH_CONF_PATH = '/etc/ssh/sshd_config'
DEF_PUB_KEY_CONF_PATH = '/etc/ssh/ssh_host_rsa_key.pub'

conf_exists = False
conf_hostname = None
conf_tokens = None
conf_server = None
conf_public_key_path = None
conf_ssh_config_path = None

if os.path.isfile(CONF_PATH):
    conf_exists = True
    with open(CONF_PATH, 'r') as conf_file:
        conf_data = conf_file.read()
        conf_data = json.loads(conf_data)
        conf_hostname = conf_data.get('hostname')
        conf_server = conf_data.get('server')
        conf_tokens = conf_data.get('tokens')
        conf_public_key_path = conf_data.get('public_key_path')
        conf_ssh_config_path = conf_data.get('ssh_config_path')

if '--config' in sys.argv[1:] or 'config' in sys.argv[1:]:
    key = sys.argv[2]

    if key == 'hostname':
        conf_hostname = sys.argv[3]
    elif key == 'server':
        server_url = urlparse.urlparse(sys.argv[3])
        conf_server = 'https://%s' % (server_url.netloc or server_url.path)
    elif key == 'public_key_path':
        conf_public_key_path = sys.argv[3]
    elif key == 'ssh_config_path':
        conf_ssh_config_path = sys.argv[3]
    elif key == 'clear-tokens':
        conf_tokens = []
    elif key == 'add-token':
        conf_tokens_set = set(conf_tokens or [])
        conf_tokens_set.add(sys.argv[3])
        conf_tokens = list(conf_tokens_set)
    elif key == 'remove-token':
        conf_tokens_set = set(conf_tokens or [])
        conf_tokens_set.remove(sys.argv[3])
        conf_tokens = list(conf_tokens_set)
    else:
        print('WARN: Unknown config option')
        sys.exit(0)

    with open(CONF_PATH, 'w') as conf_file:
        conf_file.write(json.dumps({
            'hostname': conf_hostname,
            'server': conf_server,
            'tokens': conf_tokens,
            'public_key_path': conf_public_key_path,
            'ssh_config_path': conf_ssh_config_path,
        }))

    sys.exit(0)

if not conf_exists:
    print('ERROR: Configuration file %r does not exists' % CONF_PATH)
    sys.exit(1)

if not conf_server:
    print('ERROR: Configuration does not contain Pritunl Zero server')
    sys.exit(1)

if not conf_tokens:
    print('ERROR: Configuration does not contain any tokens')
    sys.exit(1)

pub_key_path = os.path.expanduser(
    conf_public_key_path or DEF_PUB_KEY_CONF_PATH)
cert_path = pub_key_path.rsplit('.pub', 1)[0] + '-cert.pub'
ssh_conf_path = os.path.expanduser(
    conf_ssh_config_path or DEF_SSH_CONF_PATH)

hostname = conf_hostname or socket.gethostname()
if not hostname:
    print('ERROR: Hostname undefined on system and in configuration')
    sys.exit(1)

with open(pub_key_path, 'r') as ssh_file:
    public_key = ssh_file.read().strip()

cert_valid = False
if '--renew' not in sys.argv[1:] and 'renew' not in sys.argv[1:]:
    try:
        if os.path.exists(cert_path):
            cur_date = datetime.datetime.now() + \
                datetime.timedelta(minutes=10)

            status = subprocess.check_output(
                ['ssh-keygen', '-L', '-f', cert_path])

            cert_valid = True
            for line in status.splitlines():
                line = line.strip()
                if line.startswith('Valid:'):
                    line = line.split('to')[-1].strip()
                    valid_to = datetime.datetime.strptime(
                        line, '%Y-%m-%dT%H:%M:%S')
                    print('VALID_TO: %s' % valid_to)
                    if cur_date >= valid_to:
                        cert_valid = False
                        break
    except Exception as exception:
        print('WARN: Failed to get certificate expiration')
        print(str(exception))

if cert_valid:
    sys.exit(0)

class Request(BaseHTTPServer.BaseHTTPRequestHandler):
    def send_json_response(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data))
        self.wfile.close()

    def do_GET(self):
        if self.path == '/challenge':
            self.send_json_response({
                'public_key': public_key,
            })
        else:
            self.send_response(404)

server = BaseHTTPServer.HTTPServer(
    ('0.0.0.0', 9748),
    Request,
)
thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()
time.sleep(0.5)

req = urllib2.Request(
    conf_server + '/ssh/host',
    data=json.dumps({
        'tokens': conf_tokens,
        'public_key': public_key,
        'hostname': hostname,
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
        print('ERROR: ' + resp_error)
    else:
        print('ERROR: Failed to renew host certificate with state %d' %
            status_code)
        if resp_data:
            print(resp_data.strip())
    exit()

certificates = json.loads(resp_data)['certificates']

ssh_host_cert_line = 'HostCertificate ' + cert_path
ssh_config_data = ''
ssh_config_modified = True
if os.path.exists(ssh_conf_path):
    with open(ssh_conf_path, 'r') as ssh_file:
        for line in ssh_file.readlines():
            if line.startswith('HostCertificate '):
                if line.startswith(ssh_host_cert_line):
                    ssh_config_modified = False
                else:
                    continue
            ssh_config_data += line

if ssh_config_modified:
    if not ssh_config_data.endswith('\n\n'):
        if ssh_config_data.endswith('\n'):
            ssh_config_data += '\n'
        else:
            ssh_config_data += '\n\n'
    ssh_config_data += ssh_host_cert_line + '\n'

    print('SSH_CONFIG: ' + ssh_conf_path)
    with open(ssh_conf_path, 'w') as ssh_file:
        ssh_file.write(ssh_config_data)

print('SSH_CERT: ' + cert_path)
with open(cert_path, 'w') as ssh_file:
    ssh_file.write('\n'.join(certificates))

sys.exit(0)
