from __future__ import print_function

from zoran.vulnerable_hosts_report import print_it
from zoran.util import canonicalise_ip


class VulnerableHost():
    """ The details of a host's vulnerabilities."""

    def __init__(self, uuid, ip):
        self.uuid = uuid
        self.ip = ip
        self.vulnerabilities = []
        self.credentials = []

    def add_vulnerability(self, vulnerability):
        self.vulnerabilities.append(vulnerability)
        vulnerability.uuid = self.uuid
        vulnerability.ip = self.ip

    def add_credential(self, credential):
        self.credentials.append(credential)
        credential.uuid = self.uuid
        credential.ip = self.ip

    def whitelisted(self):
        """ Is a host whitelisted? Only if there are security holes
            (a vulnerability or credential) but all are white listed."""
        holes = self.vulnerabilities + self.credentials
        white_listed_holes = [h for h in holes if h.whitelisted()]
        if holes and (len(holes) == len(white_listed_holes)):
            return True
        return False

    def printable_host(self):
        """ A host's details should only be printed if it has a printable
            vulnerability or a printable credential.

            Note the difference with whitelisted(): a printable host
            may be whitelisted but still printable if CONF.list_boring
            is set to True."""
        if print_it(self.vulnerabilities) + print_it(self.credentials):
            return True
        return False


class Vulnerability:
    """ The details of a particular vulnerability."""

    def __init__(self, name, service, port):
        self.name = name
        self.service = service
        self.port = port

    # Nothing whitelisted. (yet)
    def whitelisted(self):
        """ When to whitelist a vulnerability."""
        return False

    def sort_key(self):
        """ How to sort the vulnerability dump."""
        return self.name + self.port.zfill(5) + \
            self.service + canonicalise_ip(self.ip)


class Credential:
    """ The details of a particular service with a guessable username
        and password."""

    def __init__(self, service, port, user, password):
        self.service = service
        self.port = port
        self.user = user
        self.password = password

    def whitelisted(self):
        """ When to whitelist a credential."""
        if (self.service == "ftp" and
           self.user == "anonymous" and
           self.password == "mozilla@example.com"):
            return True
        return False

    def sort_key(self):
        """ How to sort the credential dump."""
        return self.service + self.port.zfill(5) + canonicalise_ip(self.ip)
