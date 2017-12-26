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
try:
    import boto3
    HAS_BOTO = True
except:
    HAS_BOTO = False

VERSION = '1.0.763.22'
CONF_PATH = '/etc/pritunl-ssh-host.json'
DEF_SSH_CONF_PATH = '/etc/ssh/sshd_config'
DEF_PUB_KEY_CONF_PATH = '/etc/ssh/ssh_host_rsa_key.pub'

USAGE = """\
Usage: pritunl-ssh-host [command]

Commands:
  help             Show help
  version          Print the version and exit
  renew            Force certificate renewal
  info             Show current certificate information
  config           Set configuration options
    hostname         Set server hostname
    server           Set Pritunl Zero server hostname
    clear-tokens     Remove all tokens
    add-token        Add token
    remove-token     Remove token
    ssh-config-path  Set SSH server configuration path
    public-key-path  Set SSH public key path
    aws-access-key   Set AWS access key
    aws-secret-key   Set AWS secret key
    route-53-zone    Set Route 53 zone for auto DNS
    public-address   Set public IP address for Route 53
    public-address6  Set public IPv6 address for Route 53"""

conf_exists = False
conf_hostname = None
conf_tokens = None
conf_server = None
conf_public_key_path = None
conf_ssh_config_path = None
conf_aws_access_key = None
conf_aws_secret_key = None
conf_route_53_zone = None
conf_public_address = None
conf_public_address6 = None

if '--help' in sys.argv[1:] or 'help' in sys.argv[1:]:
    print(USAGE)
    sys.exit(0)

if '--version' in sys.argv[1:] or 'version' in sys.argv[1:]:
    print('pritunl-ssh-host v' + VERSION)
    sys.exit(0)

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
        conf_aws_access_key = conf_data.get('aws_access_key')
        conf_aws_secret_key = conf_data.get('aws_secret_key')
        conf_route_53_zone = conf_data.get('route_53_zone')
        conf_public_address = conf_data.get('public_address')
        conf_public_address6 = conf_data.get('public_address6')

if '--config' in sys.argv[1:] or 'config' in sys.argv[1:]:
    key = sys.argv[2]

    if key == 'hostname':
        conf_hostname = sys.argv[3]
    elif key == 'server':
        server_url = urlparse.urlparse(sys.argv[3])
        conf_server = 'https://%s' % (server_url.netloc or server_url.path)
    elif key == 'public-key-path':
        conf_public_key_path = sys.argv[3]
    elif key == 'ssh-config-path':
        conf_ssh_config_path = sys.argv[3]
    elif key == 'aws-access-key':
        conf_aws_access_key = sys.argv[3]
    elif key == 'aws-secret-key':
        conf_aws_secret_key = sys.argv[3]
    elif key == 'route-53-zone':
        conf_route_53_zone = sys.argv[3]
    elif key == 'public-address6':
        conf_public_address = sys.argv[3]
    elif key == 'public-address':
        conf_public_address6 = sys.argv[3]
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
            'aws_access_key': conf_aws_access_key,
            'aws_secret_key': conf_aws_secret_key,
            'route_53_zone': conf_route_53_zone,
            'public_address': conf_public_address,
            'public_address6': conf_public_address6,
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

if '--info' in sys.argv[1:] or 'info' in sys.argv[1:]:
    if not os.path.exists(cert_path):
        print('ERROR: No SSH certificates available')
        sys.exit(1)
    subprocess.check_call(['ssh-keygen', '-L', '-f', cert_path])
    sys.exit(0)

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

def get_public_addr():
    req = urllib2.Request(
        'https://app.pritunl.com/ip',
    )
    req.get_method = lambda: 'GET'
    resp = urllib2.urlopen(req, timeout=5)
    resp_data = resp.read()
    return json.loads(resp_data)['ip']

def set_zone_record(zone_name, host_name, ip_addr, ip_addr6):
    for i in xrange(3):
        try:
            _set_zone_record(zone_name, host_name, ip_addr, ip_addr6)
            break
        except:
            if i >= 2:
                raise
        time.sleep(1)

def _set_zone_record(zone_name, host_name, ip_addr, ip_addr6):
    client = boto3.client(
        'route53',
        aws_access_key_id=conf_aws_access_key,
        aws_secret_access_key=conf_aws_secret_key,
    )

    hosted_zone_id = None
    hosted_zone_name = None
    hosted_zones = client.list_hosted_zones_by_name()
    for hosted_zone in hosted_zones['HostedZones']:
        if zone_name in hosted_zone['Name']:
            hosted_zone_id = hosted_zone['Id']
            hosted_zone_name = hosted_zone['Name']

    if not hosted_zone_id or not hosted_zone_name:
        print('ERROR: Failed to find hosted zone ID for %r' % zone_name)
        sys.exit(1)

    record_name = host_name + '.' + hosted_zone_name

    records = client.list_resource_record_sets(
        HostedZoneId=hosted_zone_id,
    )

    cur_ip_addr = None
    cur_ip_addr6 = None

    for record in records['ResourceRecordSets']:
        if record.get('Type') not in ('A', 'AAAA'):
            continue
        if record.get('Name') != record_name:
            continue

        if len(record['ResourceRecords']) == 1:
            if record['Type'] == 'A':
                cur_ip_addr = record['ResourceRecords'][0]['Value']
            else:
                cur_ip_addr6 = record['ResourceRecords'][0]['Value']
        else:
            if record['Type'] == 'A':
                cur_ip_addr = []
            else:
                cur_ip_addr6 = []

            for val in record['ResourceRecords']:
                if record['Type'] == 'A':
                    cur_ip_addr.append(val['Value'])
                else:
                    cur_ip_addr6.append(val['Value'])

    changes = []

    if ip_addr != cur_ip_addr:
        if not ip_addr and cur_ip_addr:
            if isinstance(cur_ip_addr, list):
                vals = cur_ip_addr
            else:
                vals = [cur_ip_addr]

            resource_recs = []
            for val in vals:
                resource_recs.append({'Value': val})

            changes.append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'A',
                    'TTL': 60,
                    'ResourceRecords': resource_recs,
                },
            })
        else:
            changes.append({
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'A',
                    'TTL': 60,
                    'ResourceRecords': [
                        {'Value': ip_addr},
                    ],
                },
            })

    if ip_addr6 != cur_ip_addr6:
        if not ip_addr6 and cur_ip_addr6:
            if isinstance(cur_ip_addr6, list):
                vals = cur_ip_addr6
            else:
                vals = [cur_ip_addr6]

            resource_recs = []
            for val in vals:
                resource_recs.append({'Value': val})

            changes.append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'AAAA',
                    'TTL': 60,
                    'ResourceRecords': resource_recs,
                },
            })
        else:
            changes.append({
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'AAAA',
                    'TTL': 60,
                    'ResourceRecords': [
                        {'Value': ip_addr6},
                    ],
                },
            })

    if changes:
        client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': changes,
            },
        )

if conf_route_53_zone:
    if not HAS_BOTO:
        print('ERROR: Route53 configured but Boto library missing')
        sys.exit(1)

    if conf_public_address:
        public_addr = conf_public_address
    else:
        public_addr = get_public_addr()

    print('ROUTE53: %s %s %s' % (
        hostname + '.' + conf_route_53_zone,
        public_addr,
        conf_public_address6 or '',
    ))

    set_zone_record(
        conf_route_53_zone,
        hostname,
        public_addr,
        conf_public_address6,
    )

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
    sys.exit(1)

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
