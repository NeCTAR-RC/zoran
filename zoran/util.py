import subprocess


def cmd_exists(cmd):
    return subprocess.call("type " + cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def canonicalise_ip(ip):
    """ Put padding zeroes (if necessary) in front of each part of a
        dotted quod of an IP so that a simple dictionary sort is the
        same as a numerical sort."""
    return ".".join([q.zfill(3) for q in ip.split(".")])
