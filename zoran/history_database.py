from __future__ import print_function
from os.path import exists, isfile

import csv

from zoran.config import CONF
from util import canonicalise_date

title = ['Scan Time', 'Scan ID', 'UUID', 'Address', 'Hole Type',
         'Service', 'Port', 'Name', 'User', 'Password', 'Time Opened',
         "Time Closed"]


class HistoryDatabase:
    """ Functions relating to accessing the databse that keeps information
        on previously-encountered vulnerabilities. Apparantly the paradigm
        for working with CSV databases is to read the file into a list,
        modify the list accordingly and then write it back to the file
        once done."""

    def __init__(self):
        return None

    def open_database(self, database_file):
        """ Open a database. If the CSV file already exists, read
            from that file and put it all into a list. If not,
            create that file and write to it. Given that when the database
            is "closed" this will happen anyway, this seems redundant,
            but it reduces nasty surprises later - we don't want to do
            all the work on the database only to learn at the end that
            it couldn't be written to."""

        if exists(database_file):
            if isfile(database_file):
                database = open(database_file, 'r')
                reader = csv.reader(database)
                holes = []
                for row in reader:
                    holes.append(row)
                if holes[0] != title:
                    print('"database_file" exists and is a file, but '
                          'it\'s not the file we\'re looking for.')
                    exit()
                self.holes = holes[1:]
            else:
                print('"database_file" exists, but it\'s not a file...')
                exit()
        else:
            database = open(database_file, 'w')
            writer = csv.writer(database)
            writer.writerows([title])
            database.close()
            database = open(database_file, 'r')
            self.holes = []

        self.database_file = database_file

    def close_old_cases(self, current_hosts, scan_time):
        """ Go through the database and if a case is open in it,
            but doesn't exist in the list of current vulnerabilities,
            close it.

            NB: This should be run before open_new_cases(). """

        current_vulnerabilities = [vulnerability
                                   for sublist in [host.vulnerabilities
                                                   for host in current_hosts]
                                   for vulnerability in sublist]
        current_credentials = [credential
                               for sublist in [host.credentials
                                               for host in current_hosts]
                               for credential in sublist]

        for historical_hole in self.holes:
            found = 0
            if historical_hole[-1] is not None:
                continue
            if historical_hole[4] == "V":
                for current_vulnerability in current_vulnerabilities:
                    if historical_hole[2] == current_vulnerability.uuid and\
                       historical_hole[3] == current_vulnerability.address and\
                       historical_hole[4] == current_vulnerability.service and\
                       historical_hole[5] == current_vulnerability.port and\
                       historical_hole[6] == current_vulnerability.name:
                        found = 1
                        break
            elif historical_hole[4] == "C":
                for current_credential in current_credentials:
                    if historical_hole[2] == current_credential.uuid and\
                       historical_hole[3] == current_credential.address and\
                       historical_hole[4] == current_credential.service and\
                       historical_hole[5] == current_credential.port and\
                       historical_hole[7] == current_credential.user and\
                       historical_hole[8] == current_credential.password:
                        found = 1
                        break
            else:
                print('Strange line:\n', historical_hole, '\nIn file:',
                      CONF.database)
            if not found:
                historical_hole[-1] = canonicalise_date(scan_time)

    def open_new_cases(self, current_hosts, scan_time, scan_id):
        """ Compare the list of currently-detected security holes against
            those in the database. If the current hole is not already
            in the database (and marked open), a new (open) entry is
            put in. Otherwise, the case is deleted. As well as opening
            new cases, this function filters the list of current hosts
            so that the only ones remaining are these new ones.

            NB: This should be run after close_old_cases()."""

        for current_host in current_hosts:
            for current_vulnerability in current_host.vulnerabilities:
                found = 0
                for historical_hole in self.holes:
                    if historical_hole[2] == current_host.uuid and\
                       historical_hole[3] == current_host.ip and\
                       historical_hole[4] == "V" and\
                       historical_hole[5] == current_vulnerability.service and\
                       historical_hole[6] == current_vulnerability.port and\
                       historical_hole[7] == current_vulnerability.name and\
                       historical_hole[-1] is not None:
                        found = 1
                        break

                if found:
                    # Delete the vulnerability - we already know about it.
                    current_host.vulnerabilities.remove(current_vulnerability)
                else:
                    # Create a new entry and put it in the "database".
                    line = [scan_time,
                            scan_id,
                            current_host.uuid,
                            current_host.ip,
                            "V",
                            current_vulnerability.service,
                            current_vulnerability.port,
                            current_vulnerability.name,
                            None,
                            None,
                            canonicalise_date(scan_time),
                            None]
                    self.holes.append(line)

            for current_credential in current_host.credentials:
                found = 0
                for historical_hole in self.holes:
                    if historical_hole[2] == current_host.uuid and\
                       historical_hole[3] == current_host.ip and\
                       historical_hole[4] == "C" and\
                       historical_hole[5] == current_credential.service and\
                       historical_hole[6] == current_credential.port and\
                       historical_hole[8] == current_credential.user and\
                       historical_hole[9] == current_credential.password and\
                       historical_hole[-1] is not None:
                        found = 1
                        break

                if found:
                    # Delete the credential - we already know about it.
                    current_host.credentials.remove(current_credential)
                else:
                    line = [scan_time,
                            scan_id,
                            current_host.uuid,
                            current_host.ip,
                            "C",
                            current_credential.service,
                            current_credential.port,
                            None,
                            current_credential.user,
                            current_credential.password,
                            canonicalise_date(scan_time),
                            None]
                    self.holes.append(line)

            if not (current_host.vulnerabilities or current_host.credentials):
                current_hosts.remove(current_host)

    def close_database(self):
        """ Close a database. Everything that's going to be done
            to the list that stored the database has now been
            done so write it to a file."""
        database = open(self.database_file, 'w')
        writer = csv.writer(database)
        writer.writerows([title])
        for row in self.holes:
            writer.writerows([row])
        database.close()

    def holes_at_point_in_time(self, date):
        """" Go through a database and retrieve the cases that were open
             at the given time. """

        historical_holes = []

        date = str(date).ljust(12, '0')

        for historical_hole in self.holes:
            if historical_hole[-2] > date or historical_hole[-1] < date:
                continue
            historical_holes.append(historical_hole)

        return historical_holes
