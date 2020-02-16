import sqlite3
import os
import optparse
import csv
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

def pkt_callback(pkt):
    global quiet
    global dbaseConn

    if pkt.haslayer(DNSQR) and UDP in pkt and pkt[UDP].sport == 53:
        # pkt[IP].dst == IP source of the DNS request
        # pkt[IP].src == IP of the DNS server
        # pkt[DNS].an.rrname == DNS name
        query = pkt[DNS].an.rrname if pkt[DNS].an != None else "?"

        if not pkt[IP].dst in queries_liste:
            queries_liste[pkt[IP].dst] = {}

        if not pkt[IP].src in queries_liste[pkt[IP].dst]:
            queries_liste[pkt[IP].dst][pkt[IP].src] = {}

        if not query in queries_liste[pkt[IP].dst][pkt[IP].src]:
            queries_liste[pkt[IP].dst][pkt[IP].src][query] = 1
        else:
            queries_liste[pkt[IP].dst][pkt[IP].src][query] += 1

        if dbaseConn and query is not None and None != "?":
            dbaseCursor.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?);", (query,))
            dbaseConn.commit()

            dbaseCursor.execute("SELECT idDomain FROM domains WHERE domain=?;", (query,))
            domainId = dbaseCursor.fetchone()[0]

            dbaseCursor.execute("SELECT count, idWhoAsk FROM whoAsk WHERE ipFrom=? AND ipTo=? AND domainId=?;",
                                   (pkt[IP].src, pkt[IP].dst, domainId))
            whoAsk = dbaseCursor.fetchone()

            if whoAsk:
                dbaseCursor.execute("UPDATE whoAsk SET count=? WHERE idWhoAsk=?",
                                       (whoAsk[0] + 1 if whoAsk[0] else 2, whoAsk[1]))
            else:
                dbaseCursor.execute("INSERT INTO whoAsk (ipFrom, ipTo, domainId, count) VALUES (?,?,?,1);",
                                       (pkt[IP].src, pkt[IP].dst, domainId))

            dbaseConn.commit()

        if not quiet:
            os.system('clear')
            print("{:15s} | {:15s} | {:15s} | {}".format("IP source", "DNS server", "Count DNS request", "Query"))
            for ip in queries_liste:
                print("{:15s}".format(ip))  # IP source
                for query_server in queries_liste[ip]:
                    print(" " * 18 + "{:15s}".format(query_server))  # IP of DNS server
                    for query in queries_liste[ip][query_server]:
                        print(" " * 36 + "{:19s} {}".format(str(queries_liste[ip][query_server][query]),
                                                            query))  # Count DNS request | DNS


def connDB(ndbase):
    global dbaseConn
    global dbaseCursor

    dbaseConn = sqlite3.connect('databases/'+ndbase)  # Open a database File
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
							UNIQUE(ipFrom, ipTo, domainId),
							FOREIGN KEY(domainId) REFERENCES domains(id)
						);""")

    print 'Tables created'


def closeDB(dbase):
    dbase.close()
    print 'Database closed'


def main():
    parser = optparse.OptionParser(usage="%prog: [options]")
    parser.add_option("-i", "--iface", dest="iface", default='', help="Interface. Ex: enp0s7")
    parser.add_option("-q", "--quiet", dest="quiet", action="store_true", help="Quiet")
    parser.add_option("-d", "--database", dest="databaseName", default='dns_db',
                      help="")
    parser.add_option("-e", "--export", dest="exportPath", default='', help="Export sqlite database to CSV. Ex: db.csv")

    (options, args) = parser.parse_args()

    iface = options.iface
    quiet = options.quiet
    databaseName = options.databaseName

    connDB(databaseName)
    creatingDbaseTables()

    if options.exportPath:
        dbaseCursor.execute(
            "SELECT domain, ipFrom, ipTo, count FROM domains, whoAsk WHERE idDomain = domainId ORDER BY count DESC;")
        data = dbaseCursor.fetchall()
        with open(options.exportPath, 'w') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerows([('domain', 'ipFrom', 'ipTo', 'count')])
            writer.writerows(data)

    else:
        if not quiet:
            os.system('clear')
            print("{:15s} | {:15s} | {:15s} | {}".format("IP source", "DNS server", "Count DNS request", "Query"))

        if iface != "":
            sniff(filter='udp port 53', store=0, prn=pkt_callback, iface=iface)
        else:
            sniff(filter='udp port 53', store=0, prn=pkt_callback)


if __name__ == '__main__':
    main()
