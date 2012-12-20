#!/usr/bin/env python
"""A password store. Written in python using sqlite.

[--show] $name    Show the password for $name.  Default command.
--help, -h        Show this message.
--add $name       Add entry $name.  You will be prompted for the password. Existing entries will be replaced
--remove $name    Removes an entry
--backup [$name]  Copies to a backup file.  [default: backup]
--all             Shows the entire file (to STDOUT).
"""
import sqlite3
import os
import sys
import getpass
import hashlib
import random
import re

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.stderr.write("PyCrypto is required\n")
    sys.stderr.write("pip install pycrypto\n")
    sys.exit(1)


def get_connection(db):
    conn = sqlite3.connect(db)
    conn.text_factory = str
    return conn


def get_default_connection():
    db = os.environ.get('P_PASSWORDS_FILE')
    if not db:
        db = os.path.join(os.environ['HOME'], '.p_passwords')
    db += '.sql'
    return get_connection(db)


conn = get_default_connection()
cursor = conn.cursor()
cursor.execute('''CREATE TABLE
                    IF NOT EXISTS
                    passwords
                  (
                    name TEXT PRIMARY KEY,
                    password TEXT,
                    iv TEXT
                  )''')

if len(sys.argv) == 1:
    command_name = 'help'
    args = []
else:
    if sys.argv[1][0:2] == '--':
        command_name = sys.argv[1][2:]
        args = sys.argv[2:]
    elif sys.argv[1][0] == '-':
        command_name = sys.argv[1][1:]
        args = sys.argv[2:]
    else:
        command_name = 'show'
        args = sys.argv[1:]


def encrypt(entry, password):
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    key = hashlib.sha256(password).digest()
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    while len(entry) % 16 > 0:
        entry += chr(0)
    return encryptor.encrypt(entry), iv


def decrypt(ciphertext, password, iv):
    key = hashlib.sha256(password).digest()
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plain = decryptor.decrypt(ciphertext).rstrip(chr(0))
    char_regex = re.compile(r'[ -~]')
    is_char = lambda c: char_regex.match(c)
    if any(not is_char(c) for c in plain):
        return None
    return plain


def error_and_exit(message):
    sys.stderr.write("\033[31;1mError:\033[0m {0}\n".format(message))
    sys.exit(1)


def p_help():
    print(__doc__)
p_h = p_help


def p_show():
    name = args.pop()
    if not name:
        p_help()
        error_and_exit('$name is a required field')

    cursor.execute('SELECT password, iv FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        iv = result[1]
        ciphertext = result[0]

        password = getpass.getpass()
        plain = decrypt(ciphertext, password, iv)

        if sys.stdout.isatty():
            pbpaste = os.popen('pbpaste', 'r')
            old_board = pbpaste.read()
            pbpaste.close()

            pbcopy = os.popen('pbcopy', 'w')
            pbcopy.write(plain)
            pbcopy.close()
            sys.stderr.write("\033[1mThe password is in the clipboard\033[0m\n")
            sys.stderr.write('Press enter to clear the clipboard, or ctrl+c to abort...')
            sys.stdin.readline()

            pbcopy = os.popen('pbcopy', 'w')
            pbcopy.write(old_board)
            pbcopy.close()
        else:
            sys.stdout.write(plain)
    else:
        error_and_exit('"{0}" was not found'.format(name))


def p_add():
    name = args.pop(0)
    if not name:
        p_help()
        error_and_exit('$name is a required field')

    try:
        entry = args.pop(0)
    except IndexError:
        entry = getpass.getpass('The password for "{0}":'.format(name))

    cursor.execute('SELECT password, iv FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        password = getpass.getpass('Old:')
        try:
            if not decrypt(result[0], password, result[1]):
                error_and_exit('Old password is incorrect')
        except ValueError:
            pass

    password = getpass.getpass('Master:')
    password_verify = getpass.getpass('Verify:')

    if password_verify == password:
        cipher, iv = encrypt(entry, password)
        cursor.execute('REPLACE INTO passwords (name, password, iv) VALUES (?, ?, ?)', (name, cipher, iv))
    else:
        error_and_exit('Passwords do not match')
p_a = p_add


def p_remove():
    name = args.pop(0)
    if not name:
        p_help()
        error_and_exit('$name is a required field')

    cursor.execute('SELECT password, iv FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        password = getpass.getpass('Old:')
        try:
            if not decrypt(result[0], password, result[1]):
                error_and_exit('Old password is incorrect')
        except ValueError:
            pass
        cursor.execute('DELETE FROM passwords WHERE name = ?', [name])
    else:
        error_and_exit('Password "{0}" was not found'.format(name))
p_r = p_remove


def p_list():
    cursor.execute('SELECT name FROM passwords')
    for (name,) in cursor.fetchall():
        print(name)
p_l = p_list


##|
##|  Run the command
##|
command = locals().get('p_' + command_name)
if not command:
    command = error_and_exit('Unknown command "{0}"'.format(command_name))
else:
    try:
        command()
    except KeyboardInterrupt:
        sys.stderr.write("Aborting\n")
    cursor.close()
    conn.commit()
