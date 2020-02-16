import scapy
import sqlite3


def connDB(ndbase):
    dbase = sqlite3.connect(ndbase)  # Open a database File
    print 'Database opened'
    return dbase


def creatingDbaseTable(dbase):
    dbase.execute(''' CREATE TABLE IF NOT EXISTS employee_records(
        ID INT PRIMARY KEY NOT NULL,
        NAME TEXT NOT NULL,
        DIVISION TEXT NOT NULL,
        STARS INT NOT NULL) ''')

    print 'Table created'


def insertingRecords(dbase, records):
    dbase.execute(''' INSERT INTO employee_records(ID,NAME,DIVISION,STARS)
            VALUES(5,'James','Maintenance',4)
    ''')

    dbase.commit()
    print 'REcord inserted'


def closeDB(dbase):
    dbase.close()
    print 'Database closed'


def main():
    pass


if __name__ == '__main__':
    main()
