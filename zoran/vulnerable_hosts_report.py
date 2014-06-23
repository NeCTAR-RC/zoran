from __future__ import print_function
from jinja2 import Environment, FileSystemLoader
from zoran.config import CONF
import os.path
from operator import methodcaller
from zoran.util import canonicalise_ip

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import Utils


def print_it(value):
    """ Print the details of a vulnerability or credential? Only if it's
        not whitelisted or if the user explicitly wants it."""
    if CONF.list_boring:
        return value
    return [v for v in value if not v.whitelisted()]


def pad_ip(ip):
    """ Put padding spaces (if necessary) in front of an IP so it prints
        nicely in a text table."""
    return ip.rjust(15)


def report_scan(report_format,
                scan_time,
                scan_id,
                invalid_host_count,
                vulnerable_hosts=[]):
    """ Create a report in the format specified (i.e. html or plain
        text or mixed) and save it in a string, then present it in the
        way specified (i.e. via email or printed to the screen.)"""

    """ Scary list comprehensions that provide flat lists of all the
        vulnerabilities and credentials listed by the vulnerable hosts."""
    vulnerabilities = [vulnerability
                       for sublist in [host.vulnerabilities
                                       for host in vulnerable_hosts]
                       for vulnerability in sublist]
    credentials = [credential
                   for sublist in [host.credentials
                                   for host in vulnerable_hosts]
                   for credential in sublist]

    if report_format == "html":
        report = html_print(scan_time,
                            scan_id,
                            invalid_host_count,
                            vulnerable_hosts,
                            vulnerabilities,
                            credentials)
    elif report_format == "text":
        report = text_print(scan_time,
                            scan_id,
                            invalid_host_count,
                            vulnerable_hosts,
                            vulnerabilities,
                            credentials)
    elif report_format == "mixed":
        report_text = text_print(scan_time,
                                 scan_id,
                                 invalid_host_count,
                                 vulnerable_hosts,
                                 vulnerabilities,
                                 credentials)
        report_html = html_print(scan_time,
                                 scan_id,
                                 invalid_host_count,
                                 vulnerable_hosts,
                                 vulnerabilities,
                                 credentials)
    else:
        print("Unknown report format: %s" % report_format)
        return

    if not (vulnerable_hosts or CONF.report_empty):
        return

    # Send an email. (The default.)
    if report_format == "mixed":
        msg = MIMEMultipart('alternative')
        msg.attach(MIMEText(report_text, 'plain', 'utf-8'))
        msg.attach(MIMEText(report_html, 'html', 'utf-8'))
        msg['Subject'] = CONF.email.report_subject
        msg['From'] = CONF.email.report_from
        msg['To'] = CONF.email.report_to
        msg['Date'] = Utils.formatdate(localtime=1)
        s = smtplib.SMTP(CONF.email.smtp_server)
        s.sendmail(CONF.email.report_from,
                   CONF.email.report_to,
                   msg.as_string())
        s.quit()
    elif report_format == "html" or report_format == "text":
        print(report)


def html_print(scan_time,
               scan_id,
               invalid_host_count,
               vulnerable_hosts=[],
               vulnerabilities=[],
               credentials=[]):
    TEMPLATE_DIR = os.path.abspath(os.path.dirname(__file__))
    TEMPLATE_DIR = os.path.join(TEMPLATE_DIR, 'templates')
    templateLoader = FileSystemLoader(searchpath=TEMPLATE_DIR)
    env = Environment(loader=templateLoader)
    env.filters['print_it'] = print_it
    report = env.get_template('html.tmpl')
    return report.render(title=CONF.email.report_subject,
                         scan_time=scan_time,
                         scan_id=scan_id,
                         vulnerablehosts=sorted([h for h in vulnerable_hosts if h.printable_host()], key=lambda host: canonicalise_ip(host.ip)),
                         dump=CONF.dump,
                         vulnerabilities=sorted(vulnerabilities,
                                                key=methodcaller('sort_key')),
                         credentials=sorted(credentials,
                                            key=methodcaller('sort_key')),
                         total=len(vulnerable_hosts),
                         list_boring=CONF.list_boring,
                         white_listed=len([h for h in vulnerable_hosts if h.whitelisted()]),
                         invalid_hosts=CONF.disable_host_validation,
                         invalid_host_count=invalid_host_count)


def text_print(scan_time,
               scan_id,
               invalid_host_count,
               vulnerable_hosts=[],
               vulnerabilities=[],
               credentials=[]):
    TEMPLATE_DIR = os.path.abspath(os.path.dirname(__file__))
    TEMPLATE_DIR = os.path.join(TEMPLATE_DIR, 'templates')
    templateLoader = FileSystemLoader(searchpath=TEMPLATE_DIR)
    env = Environment(loader=templateLoader)
    env.filters['print_it'] = print_it
    env.filters['pad_ip'] = pad_ip
    report = env.get_template('text.tmpl')
    return report.render(scan_time=scan_time,
                         scan_id=scan_id,
                         vulnerablehosts=sorted([h for h in vulnerable_hosts if h.printable_host()], key=lambda host: canonicalise_ip(host.ip)),
                         dump=CONF.dump,
                         vulnerabilities=sorted(vulnerabilities,
                                                key=methodcaller('sort_key')),
                         credentials=sorted(credentials,
                                            key=methodcaller('sort_key')),
                         total=len(vulnerable_hosts),
                         list_boring=CONF.list_boring,
                         white_listed=len([h for h in vulnerable_hosts if h.whitelisted()]),
                         invalid_hosts=CONF.disable_host_validation,
                         invalid_host_count=invalid_host_count)
