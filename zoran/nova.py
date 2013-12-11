import os
from itertools import chain
from datetime import datetime

import pytz
from novaclient.v1_1 import client as nclient

from zoran.templates import TEMPLATE_ENV
from zoran.config import CONF


TEMPLATE_FILE = 'host.tmpl'


def connect():
    tenant_name = CONF.nova.admin_tenant_name
    username = CONF.nova.admin_username
    password = CONF.nova.admin_password
    url = CONF.nova.auth_url
    nova_client = nclient.Client(username=username, api_key=password,
                                 project_id=tenant_name, auth_url=url)
    return nova_client


def list_servers(client, **kwargs):

    opts = {'all_tenants': 1}
    opts.update(kwargs)
    servers = client.servers.list(search_opts=opts)

    if not len(servers) > 0:
        print "No hosts found."
        return
    return servers


def wash_servers(servers):
    for server in servers:
        host = {}
        host['uuid'] = server.id
        host['ports'] = []
        for sec_group in server.list_security_group():
            for rule in sec_group.rules:
                if '0.0.0.0/0' not in rule['ip_range'].values():
                    continue
                if 'icmp' == rule['ip_protocol']:
                    continue
                if rule['from_port'] == rule['to_port']:
                    port = rule['from_port']
                else:
                    port = '%s-%s' % (rule['from_port'], rule['to_port'])
                host['ports'].append(
                    {'id': rule['id'],
                     'parent_group_id': rule['parent_group_id'],
                     'range': port})

        ips = [a for a in chain(*server.networks.values())]
        for ip in ips:
            h = host.copy()
            h['ip'] = ip
            yield h


def export_servers(servers, fd):
    context = {'hosts': servers,
               'now': datetime.now(pytz.timezone("UTC"))}
    tmpl = TEMPLATE_ENV.get_template(TEMPLATE_FILE)
    fd.write(tmpl.render(context))
