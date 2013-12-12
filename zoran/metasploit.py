from os import path
import subprocess
import tempfile

from dateutil.parser import parse

from zoran import MODULE_PATH, RESOURCE_PATH
from zoran.templates import TEMPLATE_ENV


TEMPLATE_FILE = 'scan.rc'
METASPLOIT = 'msfconsole'


def wash_host(host):
    """Clean up XML from Metasploit into a python dict."""
    host = dict(host.items())
    for old_key, new_key in [('host_detail', 'host-detail'),
                             ('exploit_attempt', 'exploit-attempt')]:

        host[new_key + 's'] = host.pop(old_key + 's')
        if host[new_key + 's']:
            host[new_key + 's'][new_key] = host[new_key + 's'].pop(old_key)

    for key in ['note', 'service', 'cred', 'vuln',
                'host-detail', 'exploit-attempt']:
        if host[key + 's']:
            if not isinstance(host[key + 's'][key], list):
                host[key + 's'][key] = [host[key + 's'][key]]
        else:
            host[key + 's'] = []
            continue
        host[key + 's'] = [dict(v.items()) for v in host[key + 's'][key]]

    # Convert notes list to dict
    new_notes = {}
    for note in host['notes']:
        new_notes[note['ntype']] = note
    host['notes'] = new_notes

    # Set host uuid from notes
    host['uuid'] = host['notes']['openstack-uuid']['data']

    host.pop('service-count', None)
    host.pop('vuln-count', None)
    host.pop('cred-count', None)
    host.pop('host-detail-count', None)
    host.pop('exploit-attempt-count', None)
    host['updated-at'] = parse(host['updated-at'])
    host['created-at'] = parse(host['created-at'])

    # Clean up host notes
    for note in host['notes'].values():
        note.pop('id', None)
        note.pop('host-id', None)
        note.pop('workspace-id', None)
        if note.get('service-id', None):
            note['service-id'] = host['uuid'] + "." + note['service-id']
        note['updated-at'] = parse(note['updated-at'])
        note['created-at'] = parse(note['created-at'])

    # Clean up services
    for service in host['services']:
        service['id'] = host['uuid'] + "." + service['id']
        service.pop('host-id', None)
        service['updated-at'] = parse(service['updated-at'])
        service['created-at'] = parse(service['created-at'])

    # Clean up exploits
    for exploit in host['exploit-attempts']:
        exploit['id'] = host['uuid'] + "." + exploit['id']
        if exploit['service-id']:
            exploit['service-id'] = host['uuid'] + "." + exploit['service-id']
        exploit.pop('host-id', None)
        exploit['attempted-at'] = parse(exploit['attempted-at'])
    return host


def scan(input_file, output_file, uuid, drop=True, interactive=False):

    context = {}
    context['scan_id'] = uuid
    context['drop_database'] = True
    context['resource_path'] = RESOURCE_PATH
    context['input_file'] = path.abspath(input_file)
    context['output_file'] = path.abspath(output_file)
    tmpl = TEMPLATE_ENV.get_template(TEMPLATE_FILE)
    fd = tempfile.NamedTemporaryFile(prefix='scan')
    fd.write(tmpl.render(context))
    fd.flush()
    # TODO If there is an error in the script then this will just keep
    # running.  We need to either prevent metasploit from dropping to
    # interactive console or detect the prompt.
    args = [METASPLOIT,
            '-m', MODULE_PATH,
            '-r', fd.name]

    if not interactive:
        # TODO this file needs to be saved somewhere or read back to
        # the user for logging.
        fd1 = tempfile.NamedTemporaryFile(prefix='scan-output')
        args.extend(['-o', fd1.name])

    subprocess.call(" ".join(args), shell=True)
