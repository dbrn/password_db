import argparse
import datetime
import sqlite3
from random import randrange
from pyperclip import copy


def copy_to_clipboard(password):
    copy(str(password))
    print("Password copied to clipboard")


def print_data(data):
    print("ID\tPASSWORD\tSERVICE\tUSERNAME\tCREATION DATE\n")
    for row in data:
        for word in row:
            print(word, end="\t")
        print()
    print()


def generate_password(length):
    for i in range(length):
        rnd = randrange(33, 126)
        if rnd == 96 or rnd == 39 or rnd == 34:
            i -= 1
            continue
        yield chr(rnd)


def save_password(service, password, user, db_name):
    connection, cursor = connect(db_name)
    date = str(datetime.date.today())
    cursor.execute(f"INSERT INTO pwd_table(password, service, username, data) VALUES('{password}', '{service}', '{user}', '{date}')")
    cursor.commit()
    connection.close()


def check_existing_table(db_name):
    connection, cursor = connect(db_name)
    try:
        cursor.execute("CREATE TABLE pwd_table(id INTEGER UNIQUE NOT NULL PRIMARY KEY AUTOINCREMENT, "
                       "password VARCHAR(20), service VARCHAR(20), username VARCHAR(20), data DATE);")
    except sqlite3.OperationalError:
        connection.close()
    connection.close()


def connect(db_name):
    connection = sqlite3.connect(db_name)
    cursor = connection.cursor()
    return cursor, connection


def main():
    db_name = "pwd_db.db"
    check_existing_table(db_name)
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--retrieve", help="retrieve a Password by id# or service name", nargs=1)
    group.add_argument("-n", "--new", help="create a new password, the arguments are the service name,"
                                           " its length in chars and the username", nargs=3, type=str)
    group.add_argument("-d", "--delete", help="delete an entry by id# or service name", nargs=1)
    group.add_argument("-u", "--update", help="updates the value of an entry, argument is id# or service name"
                                              " and the new password", nargs=2)
    group.add_argument("-l", "--list", help="lists the whole database", action="store_true")
    args = parser.parse_args()
    if args.list:
        cursor, connection = connect(db_name)
        data = cursor.execute("SELECT * FROM pwd_table")
        print_data(data.fetchall())
    elif args.retrieve:
        service_path = False
        cursor, connection = connect(db_name)
        try:
            id_num = int(args.retrieve[0])
        except ValueError:
            service_name = args.retrieve[0]
            service_path = True
        try:
            if service_path:
                data = cursor.execute(f"SELECT * FROM pwd_table WHERE service='{service_name}'")
            else:
                data = cursor.execute(f"SELECT * FROM pwd_table WHERE id={id_num}")
        except sqlite3.OperationalError:
            print("Entry not found")
            connection.close()
            return
        print_data(data.fetchall())
        if service_path:
            data2 = cursor.execute(f"SELECT password FROM pwd_table WHERE service='{service_name}'")
        else:
            data2 = cursor.execute(f"SELECT password FROM pwd_table WHERE id={id_num}")
        password = data2.fetchall()
        copy_to_clipboard(password[0][0])
        connection.close()
    if args.new:
        service = args.new[0]
        username = args.new[2]
        length = int(args.new[1])
        if length > 20:
            print(f"{length} chars is too long for a password. It must be less or equal to 20 chars")
            return
        end = False
        while end is False:
            password = "".join(list(generate_password(length)))
            while True:
                print(f"Accept password {password} ? (y/n)", end=" ")
                response = input()
                if response == "y":
                    save_password(service, password, username, db_name)
                    copy_to_clipboard(password)
                    print("Entry saved")
                    end = True
                    break
                elif response == "n":
                    end = False
                    break
                else:
                    print("Please answer y or n to the question")
                    continue
    if args.delete:
        service_path = False
        cursor, connection = connect(db_name)
        try:
            id_num = int(args.delete[0])
        except ValueError:
            service_name = args.delete[0]
            service_path = True
        try:
            if service_path:
                cursor.execute(f"DELETE FROM pwd_table WHERE service='{service_name}'")
            else:
                cursor.execute(f"DELETE FROM pwd_table WHERE id={id_num}")
        except sqlite3.OperationalError:
            print("Operational error. Rolling back")
            connection.rollback()
            connection.close()
            return
        print(f"Entry deleted")
        connection.commit()
        connection.close()
    if args.update:
        password = str(args.update[1])
        length = len(password)
        if length > 20:
            print(f"{length} chars is too long for a password. It must be less or equal to 20 chars")
            return
        service_path = False
        cursor, connection = connect(db_name)
        try:
            id_num = int(args.update[0])
        except ValueError:
            service_name = args.update[0]
            service_path = True
        try:
            if service_path:
                cursor.execute(f"UPDATE pwd_table SET password='{password}' WHERE service='{service_name}'")
            else:
                cursor.execute(f"UPDATE pwd_table SET password='{password}' WHERE id={id_num}")
        except sqlite3.OperationalError:
            print("Operational error. Rolling back")
            connection.rollback()
            connection.close()
            return
        print(f"Entry updated with password {password}")
        copy_to_clipboard(password)
        connection.commit()
        connection.close()


if __name__ == "__main__":
    main()
