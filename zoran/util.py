import subprocess
import re


def cmd_exists(cmd):
    return subprocess.call("type " + cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def canonicalise_ip(ip):
    """ Put padding zeroes (if necessary) in front of each part of a
        dotted quod of an IP so that a simple dictionary sort is the
        same as a numerical sort."""
    return ".".join([q.zfill(3) for q in ip.split(".")])


def canonicalise_date(date):
    """ Take the date in the format given by the Scan Time, and return
        it in the form YYYYMMDDHHmm."""

    m = re.search('^(\d{4})-(\d\d)-(\d\d)\s(\d\d):(\d\d)', date)
    return m.group(1) + m.group(2) + m.group(3) + m.group(4) + m.group(5)
