# ZORAN the protector

Why the name? http://www.reuters.com/article/2008/03/13/idUSL13835831

## Install

First install Metasploit https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment


Setup NeCTAR module for metasploit:

    git clone https://github.com/NeCTAR/zoran.git
    cd zoran
    pip install -e .

Setup the metasploit database
http://fedoraproject.org/wiki/Metasploit_Postgres_Setup

## Usage

### Gathering Hosts

First we need to gather some data to prime the Metasploit database
with.  Using the security groups that target a public address space we
can limit the time it takes to scan.

    ./bin/gather-hosts --ip '^192.168.1.1$' target_hosts.xml

This will create an XML file with a list of hosts and their
interesting security groups.

### Scanning Hosts

Scanning is performed by Metasploit subprocess.  The scan will target
the hosts gathered in the previous step.  It will first do a port scan
on each host then target services looking for common exploits.

    ./bin/scan-hosts target_hosts.xml report.XML

### Reporting

This is currently still in development, but the current implementation
gathers hosts and confirms that the host is the same host as when it
gathered.  The XML for that host is then cleaned and put into a MongoDB.

    ./bin/ingest-scan --ip '^192.168.1.1$' report.xml
