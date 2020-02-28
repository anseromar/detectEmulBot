# coding: utf-8
from pprint import pprint
from bson import Regex
from bson.code import Code

from argparse import ArgumentParser
import os
import optparse
import csv
import time
import datetime
from bisect import bisect_left
import sys
import pymongo

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

#####################################
queries_liste = {}
quiet = False
#####################################
client = pymongo.MongoClient()
#####################################
now = time.time()
now_plus_5 = now + 60
now_plus_10 = now + 120
now_plus_15 = now + 180
tlist = [now, now_plus_5, now_plus_10, now_plus_15]


####################################

def pkt_callback(pkt):
    global quiet
    global db

    if pkt.haslayer(DNSQR) and UDP in pkt and pkt[UDP].dport == 53:
        # pkt[IP].dst == IP source of the DNS request
        # pkt[IP].src == IP of the DNS server
        # pkt[DNS].an.rrname == DNS name

        timestamp = str(bisect_left(tlist, pkt.time, lo=0, hi=len(tlist)))

        query = pkt[DNS].qd.qname if pkt[DNS].qd is not None else "?"

        query_dot = query.replace('[', '').replace(']', '').replace('.', '_')

        if not db.dnsq.find_one({'timestamp': timestamp}):
            db.dnsq.insert(
                {'timestamp': timestamp, 'domainip': [{'domain': query_dot, 'ips': [pkt[IP].src], 'lenip': 1}]})

        if db.dnsq.find_one({'timestamp': timestamp, 'domainip.domain': query_dot}) is None:
            db.dnsq.update({'timestamp': timestamp},
                           {'$push': {'domainip': {'domain': query_dot, 'ips': [], 'lenip': 0}}}, upsert=False,
                           multi=True)

        pipeline= [{
            "$match": {
                "timestamp": timestamp
                }
            },
            {
                "$unwind": "$domainip"
            },
            {
            "$match": {
                "domainip.domain": query_dot,
                "domainip.ips": {
                        "$in": [
                              pkt[IP].src
                        ]
            }
            }
        }]

        result = list(db.dnsq.aggregate(pipeline))

        if not result:
            db.dnsq.update({'timestamp': timestamp, 'domainip.domain': query_dot},
                           {'$push': {'domainip.$.ips': pkt[IP].src}, '$inc': {'domainip.$.lenip': 1}}, upsert=False,
                           multi=True)

        # print queries_liste

        # if not quiet:
        #     os.system('clear')
        #     print(
        #         "{:20s} | {:15s} | {:15s} | {}".format("(IP source, Timestamp)", "DNS server", "Count DNS request",
        #                                                "Query",
        #                                                ))
        #     for (ip, t) in queries_liste:
        #         print("{:15s}".format((ip, t)))  # IP source, timestamp
        #         for query_server in queries_liste[(ip, t)]:
        #             print(" " * 25 + "{:30s}".format(query_server))  # IP of DNS server
        #             for query in queries_liste[(ip, t)][query_server]:
        #                 print(" " * 45 + "{:18s} {}".format(str(queries_liste[(ip, t)][query_server][query]),
        #                                                     query))  # Count DNS request | DNS


def connDB(ndbase):
    global db
    global dnsq

    db = client[ndbase]  # Open a database File

    print 'Database opened'


def cleanDB(ndbase):
    pass


def closeDB(dbase):
    dbase.close()
    print 'Database closed'


def deleteDnsQuery():
    pass

    # for doc in db.dnsq.find():
    #     pprint(doc)

    # db.dnsq.update({}, {'$pull': {'domainip': {'ips': {'$where': {'ips.length < 3'}}}}}, upsert=False, multi=True)
    # db.collection.update({}, {"$pull": {"foo.bar": {"$lt": 4}}}, {"multi": true});
    db.dnsq.update({}, {'$pull': {'domainip': {'lenip': {'$lt': 3}}}}, upsert=False, multi=True)


def detectBotnet():
    result =[]
    for i in range(1, 5):
        result.append(list(db.dnsq.aggregate([{
                "$match": {
                    "timestamp": str(i)
                    }
                }])))

    lresult = len(result)
    index = 0

    for j in result:
        index = index + 1
        for domainip in j[0]['domainip']:
            domain = domainip['domain']
            for k in range(index, lresult):
                for ddoaminip in result[index][0]['domainip']:
                    i=1 if ddoaminip['domain'] == domain else False
                break
        break


def stopfilter(pkt):
    return True if pkt.time > now_plus_15 else False


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




    # # creatingDbaseTables()
    #
    # if iface != "":
    #     sniff(filter='udp port 53', store=0, prn=pkt_callback, iface=iface, stop_filter=stopfilter)
    # else:
    #     sniff(filter='udp port 53', store=0, prn=pkt_callback, stop_filter=stopfilter)
    #
    # print "####### DeleteDnsQuery ##########"
    #
    # deleteDnsQuery()

    detectBotnet()


if __name__ == '__main__':
    main()
