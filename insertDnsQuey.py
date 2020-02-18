from argparse import ArgumentParser
import sqlite3
import os
import optparse
import csv
import time
import datetime
from bisect import bisect_left

try:
    from scapy.all import sniff
    from scapy.all import ARP
    from scapy.all import DNSQR
    from scapy.all import UDP
    from scapy.all import IP
    from scapy.all import DNS
except ImportError:
    from sys import exit

    exit("\033[31mYou need to setup python-scapy\033[0m\nsudo apt install python-scapy")

queries_liste = {}
quiet = False

now = time.time()
now_plus_5 = now + 300
now_plus_10 = now + 600
now_plus_15 = now + 900
tlist = [now, now_plus_5, now_plus_10, now_plus_15]


def pkt_callback(pkt):
    global quiet
    global dbaseConn

    if pkt.haslayer(DNSQR) and UDP in pkt and pkt[UDP].sport == 53:
        # pkt[IP].dst == IP source of the DNS request
        # pkt[IP].src == IP of the DNS server
        # pkt[DNS].an.rrname == DNS name

        timestamp = str(bisect_left(tlist, pkt.time, lo=0, hi=len(tlist)))
        query = pkt[DNS].an.rrname if pkt[DNS].an is not None else "?"

        if not (pkt[IP].dst, timestamp) in queries_liste:
            queries_liste[(pkt[IP].dst, timestamp)] = {}

        if not pkt[IP].src in queries_liste[(pkt[IP].dst, timestamp)]:
            queries_liste[(pkt[IP].dst, timestamp)][pkt[IP].src] = {}

        if not query in queries_liste[(pkt[IP].dst, timestamp)][pkt[IP].src]:
            queries_liste[(pkt[IP].dst, timestamp)][pkt[IP].src][query] = 1
        else:
            queries_liste[(pkt[IP].dst, timestamp)][pkt[IP].src][query] += 1

        if dbaseConn and query is not None and None != "?":
            dbaseCursor.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?);", (query,))
            dbaseConn.commit()

            dbaseCursor.execute("SELECT idDomain FROM domains WHERE domain=?;", (query,))
            domainId = dbaseCursor.fetchone()[0]

            dbaseCursor.execute("SELECT count, idWhoAsk FROM whoAsk WHERE ipFrom=? AND ipTo=? AND domainId=? AND timestamp=?;",
                                (pkt[IP].dst, pkt[IP].src, domainId, timestamp))
            whoAsk = dbaseCursor.fetchone()

            if whoAsk:
                dbaseCursor.execute("UPDATE whoAsk SET count=? WHERE idWhoAsk=?",
                                        (whoAsk[0] + 1 if whoAsk[0] else 2, whoAsk[1]))
            else:
                dbaseCursor.execute("INSERT INTO whoAsk (ipFrom, ipTo, domainId, count, timestamp) VALUES (?,?,?,1,?);",
                                    (pkt[IP].dst, pkt[IP].src, domainId, timestamp))
            dbaseConn.commit()

        if not quiet:
            os.system('clear')
            print(
                "{:20s} | {:15s} | {:15s} | {}".format("(IP source, Timestamp)", "DNS server", "Count DNS request", "Query",
                                                                ))
            for (ip, t) in queries_liste:
                print("{:15s}".format((ip, t)))  # IP source, timestamp
                for query_server in queries_liste[(ip, t)]:
                    print(" " * 15 + "{:15s}".format(query_server))  # IP of DNS server
                    for query in queries_liste[(ip, t)][query_server]:
                        print(" " * 30 + "{:19s} {}".format(str(queries_liste[(ip,t)][query_server][query]),
                                                            query))  # Count DNS request | DNS


def connDB(ndbase):
    global dbaseConn
    global dbaseCursor

    dbaseConn = sqlite3.connect(ndbase)  # Open a database File
    dbaseCursor = dbaseConn.cursor()
    print 'Database opened'


def creatingDbaseTables():
    dbaseCursor.execute("""CREATE TABLE if not exists domains (
							idDomain INTEGER PRIMARY KEY AUTOINCREMENT,
							domain TEXT DEFAULT NULL,
							UNIQUE(domain)
						);""")
    dbaseCursor.execute("""CREATE TABLE if not exists whoAsk (
							idWhoAsk INTEGER PRIMARY KEY AUTOINCREMENT,
							ipFrom TEXT DEFAULT NULL,
							ipTo TEXT DEFAULT NULL,
							domainId INTEGER,
							count INTEGER,
							timestamp TEXT DEFAULT NULL,
							UNIQUE(ipFrom, ipTo, domainId, timestamp),
							FOREIGN KEY(domainId) REFERENCES domains(id)
						);""")

    print 'Tables created'


def stopfilter(pkt):
    return False


def cleanDB(ndbase):
    pass


def closeDB(dbase):
    dbase.close()
    print 'Database closed'


def main():
    parser = ArgumentParser()
    parser.add_argument("-i", "--iface", dest="iface", default='', help="Interface. Ex: enp0s7")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", help="Quiet")
    parser.add_argument("-d", "--database", dest="databaseName", default='dns_db', help="")
    parser.add_argument("-e", "--export", dest="exportPath", default='',
                        help="Export sqlite database to CSV. Ex: db.csv")

    args = parser.parse_args()

    iface = args.iface
    quiet = args.quiet
    databaseName = args.databaseName

    connDB(databaseName)
    creatingDbaseTables()

    if args.exportPath:
        dbaseCursor.execute(
            "SELECT domain, ipFrom, ipTo, count FROM domains, whoAsk WHERE idDomain = domainId ORDER BY count DESC;")
        data = dbaseCursor.fetchall()
        with open(args.exportPath, 'w') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerows([('domain', 'ipFrom', 'ipTo', 'count')])
            writer.writerows(data)

    else:
        if not quiet:
            os.system('clear')
            print(
                "{:20s} | {:15s} | {:15s} | {}".format("(IP source, Timestamp)", "DNS server", "Count DNS request",
                                                       "Query",
                                                       ))
        if iface != "":
            sniff(filter='udp port 53', store=0, prn=pkt_callback, iface=iface, stop_filter=stopfilter)
        else:
            sniff(filter='udp port 53', store=0, prn=pkt_callback, stop_filter=stopfilter)


if __name__ == '__main__':
    main()
