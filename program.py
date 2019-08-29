import argparse
import datetime
import sqlite3
from getpass import getpass
from os import remove, path, rename
from random import randrange

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pyperclip import copy


def encrypt_database(database_name, password):
    chunk_size = 64 * 1024
    output_filename = "e_" + database_name
    filesize = str(path.getsize(database_name)).zfill(16)
    password = SHA256.new(password.encode("utf-8")).digest()
    iv = Random.new().read(16)
    encryptor = AES.new(password, AES.MODE_CBC, iv)
    with open(database_name, "rb") as infile:
        with open(output_filename, "wb") as outfile:
            outfile.write(filesize.encode("utf-8"))
            outfile.write(iv)
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                if len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))
    remove(database_name)
    rename(output_filename, database_name)


def decrypt_database(database_name, password):
    chunk_size = 64 * 1024
    password = SHA256.new(password.encode("utf-8")).digest()
    output_filename = "temp_" + database_name
    with open(database_name, "rb") as infile:
        file_size = int(infile.read(16))
        iv = infile.read(16)
        decryptor = AES.new(password, AES.MODE_CBC, iv)
        with open(output_filename, "wb") as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(file_size)
    remove(database_name)
    rename(output_filename, database_name)


def check_master_password(password, keyfile):
    print()
    password = SHA256.new(password.encode("utf-8")).digest()
    with open(keyfile, "rb") as file:
        master_from_file = file.readline()
    if master_from_file == password:
        return True
    else:
        return False


def copy_to_clipboard(password):
    copy(str(password))
    print("Password copied to clipboard")


def print_data(data):
    print("ID\tPASSWORD\tSERVICE\tUSERNAME\tCREATION DATE\n".expandtabs(20))
    for row in data:
        entry = ""
        for word in row:
            entry += str(word) + "\t"
        print(entry.expandtabs(20))
    print()


def generate_password(length):
    i = 0
    while i < length:
        rnd = randrange(33, 126)
        if rnd == 96 or rnd == 39 or rnd == 34:
            continue
        i += 1
        yield chr(rnd)


def save_password(service, password, user, db_name):
    connection, cursor = connect(db_name)
    date = str(datetime.date.today())
    cursor.execute(
        f"INSERT INTO pwd_table(password, service, username, data) VALUES('{password}', '{service}', '{user}', '{date}')")
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
    key_file = "master.key"
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--retrieve", help="retrieve a Password by id# or service name", nargs=1)
    group.add_argument("-n", "--new", help="create a new password, the arguments are the service name,"
                                           " its length in chars and the username", nargs=3, type=str)
    group.add_argument("-d", "--delete", help="delete an entry by id# or service name", nargs=1)
    group.add_argument("-u", "--update", help="updates the value of an entry, argument is id# or service name"
                                              " and the new password", nargs=2)
    group.add_argument("-l", "--list", help="lists the whole database", action="store_true")
    group.add_argument("-init", "--initialize", help="Initializes a new database encrypted with the"
                                                     "entered password (type it twice)", nargs=2, type=str)
    args = parser.parse_args()
    if args.initialize:
        key_file_exists = path.exists(key_file)
        if key_file_exists:
            password = getpass("Insert master password: ")
            if check_master_password(password, key_file) is False:
                print("Wrong password")
                return
        db_password = args.initialize[0]
        if db_password != args.initialize[1]:
            print("Password misspelled")
            return
        else:
            remove(db_name)
            if key_file_exists:
                remove(key_file)
            print("Old database and master-key removed")
            check_existing_table(db_name)
            print("New database created")
            hash_pwd = SHA256.new(db_password.encode("utf-8")).digest()
            with open(key_file, "wb") as file:
                file.write(hash_pwd)
            print("New master-key set")
            print("Encrypting database")
            encrypt_database(db_name, db_password)
    elif path.exists(key_file) is False:
        print("Please initialize a new database")
        return
    elif args.list:
        password = getpass("Insert master password: ")
        if check_master_password(password, key_file) is False:
            print("Wrong password")
            return
        decrypt_database(db_name, password)
        check_existing_table(db_name)
        cursor, connection = connect(db_name)
        data = cursor.execute("SELECT * FROM pwd_table")
        print_data(data.fetchall())
        encrypt_database(db_name, password)
    elif args.retrieve:
        password = getpass("Insert master password: ")
        if check_master_password(password, key_file) is False:
            print("Wrong password")
            return
        decrypt_database(db_name, password)
        check_existing_table(db_name)
        service_path = False
        cursor, connection = connect(db_name)
        if str(args.retrieve[0]).isdigit() is True:
            id_num = int(args.retrieve[0])
        else:
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
            encrypt_database(db_name, password)
            return
        print_data(data.fetchall())
        if service_path:
            data2 = cursor.execute(f"SELECT password FROM pwd_table WHERE service='{service_name}'")
        else:
            data2 = cursor.execute(f"SELECT password FROM pwd_table WHERE id={id_num}")
        fetched_password = data2.fetchall()
        try:
            copy_to_clipboard(fetched_password[0][0])
        except IndexError:
            print("IndexError, db is probably empty or the wrong id#/service was entered")
        connection.close()
        encrypt_database(db_name, password)
    if args.new:
        password = getpass("Insert master password: ")
        if check_master_password(password, key_file) is False:
            print("Wrong password")
            return
        decrypt_database(db_name, password)
        check_existing_table(db_name)
        service = args.new[0]
        username = args.new[2]
        length = int(args.new[1])
        if length > 20:
            print(f"{length} chars is too long for a password. It must be less or equal to 20 chars")
            encrypt_database(db_name, password)
            return
        end = False
        while end is False:
            password_gen = "".join(list(generate_password(length)))
            while True:
                print(f"Accept password {password_gen} ? (y/n)", end=" ")
                response = input()
                if response == "y":
                    save_password(service, password_gen, username, db_name)
                    copy_to_clipboard(password_gen)
                    print("Entry saved")
                    end = True
                    break
                elif response == "n":
                    end = False
                    break
                else:
                    print("Please answer y or n to the question")
                    continue
        encrypt_database(db_name, password)
    if args.delete:
        password = getpass("Insert master password: ")
        if check_master_password(password, key_file) is False:
            print("Wrong password")
            return
        decrypt_database(db_name, password)
        check_existing_table(db_name)
        service_path = False
        cursor, connection = connect(db_name)
        if str(args.delete[0]).isdigit() is True:
            id_num = int(args.delete[0])
        else:
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
            encrypt_database(db_name, password)
            return
        print(f"Entry deleted")
        connection.commit()
        connection.close()
        encrypt_database(db_name, password)
    if args.update:
        password = getpass("Insert master password: ")
        if check_master_password(password, key_file) is False:
            print("Wrong password")
            return
        decrypt_database(db_name, password)
        check_existing_table(db_name)
        password_up = str(args.update[1])
        length = len(password_up)
        if length > 20:
            print(f"{length} chars is too long for a password. It must be less or equal to 20 chars")
            encrypt_database(db_name, password)
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
                cursor.execute(f"UPDATE pwd_table SET password='{password_up}' WHERE service='{service_name}'")
            else:
                cursor.execute(f"UPDATE pwd_table SET password='{password_up}' WHERE id={id_num}")
        except sqlite3.OperationalError:
            print("Operational error. Rolling back")
            connection.rollback()
            connection.close()
            encrypt_database(db_name, password)
            return
        print(f"Entry updated with password {password_up}")
        copy_to_clipboard(password)
        connection.commit()
        connection.close()
        encrypt_database(db_name, password)


if __name__ == "__main__":
    main()
