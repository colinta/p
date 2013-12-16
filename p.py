#!/usr/bin/env python
"""A password store. Written in python, uses sqlite.

This is designed to run on Mac OS X, and uses the `pbcopy` and `pbpaste`
commands. If you would like to adapt this to use `xsel`, please fork and
contribute your patch!  https://github.com/colinta/p

[--show] $name       Show the password for $name.  Default command.
--help, -h           Show this message.
--add, -a $name      Add entry $name.  You will be prompted for the password.
                     Existing entries will be replaced
--user, -u $name     Add a username to the entry $name.  You will be prompted
                     for the username.
--remove, -r $name   Removes an entry
--list, l            Lists all the entry names (no passwords are shown)
--file, f            Show the password file being used
--merge, -m [$file]  Merges entries from another p_password.sql store
--check              Tries to decrypt entries using the "Master" password. Any
                     entries that fail are printed to the screen
--backup, -b $file   Make a backup of the password store
--generate, --gen, -g $length $name
                     Create a new entry
"""
import sqlite3
import os
import sys
import getpass
import hashlib
import random
import re
import json


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


def get_passwords_file():
    db = os.environ.get('P_PASSWORDS_FILE')
    if not db:
        db = os.path.join(os.environ['HOME'], '.p_passwords.sql')
    return db


def get_default_connection():
    return get_connection(get_passwords_file())


def generate_password(length=20):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`-=~!@#$%^&*()_+[]\{}|;:",./<>?'
    entropy = random.SystemRandom()
    password = ''
    while length:
        password += entropy.choice(chars)
        length -= 1
    return password


def migrate(migrate_cursor):
    migrate_cursor.execute('''CREATE TABLE
                        IF NOT EXISTS
                        password_migrations
                      (
                        version INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT
                      )''')

    migrate_cursor.execute('SELECT MAX(version) FROM password_migrations')
    result = migrate_cursor.fetchone()[0] or 0
    if result < 1:
        migrate_cursor.execute('''CREATE TABLE
                            IF NOT EXISTS
                            passwords
                          (
                            name TEXT PRIMARY KEY,
                            password TEXT,
                            iv TEXT
                          )''')
        migrate_cursor.execute('INSERT INTO password_migrations (name) VALUES (?)', ['Initial commit'])
    if result < 2:
        migrate_cursor.execute('ALTER TABLE passwords ADD COLUMN username TEXT DEFAULT ""')
        migrate_cursor.execute('INSERT INTO password_migrations (name) VALUES (?)', ['Add username column'])


conn = get_default_connection()
cursor = conn.cursor()
migrate(cursor)


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
    sys.stderr.write("\033[1mError: \033[31m{0}\033[0m\n".format(message))
    sys.exit(1)


def p_help(args=[]):
    print(__doc__)
p_h = p_help


def pbcopy(content):
    sock = os.popen('pbcopy', 'w')
    sock.write(content)
    sock.close()


def pbpaste():
    sock = os.popen('pbpaste', 'r')
    old_board = sock.read()
    sock.close()
    return old_board

def p_show(args):
    name = args.pop()
    if not name:
        p_help()
        error_and_exit('$name is a required field')

    cursor.execute('SELECT password, iv, username FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        ciphertext = result[0]
        iv = result[1]
        username = result[2]

        password = getpass.getpass()
        plain = decrypt(ciphertext, password, iv)

        if sys.stdout.isatty():
            old_board = pbpaste()

            if username:
                sys.stderr.write("\033[1mThe username is in the clipboard\033[0m\n")
                sys.stderr.write("\033[1mUsername:\033[0m ")
                sys.stderr.write(username)
                sys.stderr.write("\n")
                sys.stderr.write('Press enter to copy the password, or ctrl+c to abort...')
                pbcopy(username)
                sys.stdin.readline()

            sys.stderr.write("\033[1mThe password is in the clipboard\033[0m\n")
            sys.stderr.write('Press enter to restore the clipboard, or ctrl+c to abort...')
            pbcopy(plain)
            sys.stdin.readline()

            pbcopy(old_board)
        else:
            sys.stdout.write(plain)
    else:
        sys.stdout.write('"{0}" was not found, should I make an entry? [y]: '.format(name))
        should_add = sys.stdin.readline()[:-1]  # strip \n
        if should_add == '' or should_add == 'y':
            p_generate([20, name])
        else:
            error_and_exit('aborting'.format(name))


def p_generate(args):
    try:
        length = args.pop(0)
    except IndexError:
        length = None

    if not length:
        p_help()
        error_and_exit('$length is a required field')

    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        p_help()
        error_and_exit('$name is a required field')

    plain = generate_password()
    p_add([name], plain)

    old_board = pbpaste()
    pbcopy(plain)

    sys.stderr.write("\033[1mThe password is in the clipboard\033[0m\n")
    sys.stderr.write('Press enter to clear the clipboard, or ctrl+c to abort...')
    sys.stdin.readline()

    pbcopy(old_board)
p_g = p_generate
p_gen = p_generate

def p_add(args, entry=None):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        p_help()
        error_and_exit('$name is a required field')

    if not entry:
        entry = getpass.getpass('The password for "{0}": '.format(name))

    cursor.execute('SELECT password, iv FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        password = getpass.getpass('Old: ')
        try:
            if not decrypt(result[0], password, result[1]):
                error_and_exit('Old password is incorrect')
        except ValueError:
            pass

    password = getpass.getpass('Master: ')
    password_verify = getpass.getpass('Verify: ')

    if password == '':
        error_and_exit('Password must not be blank')
    elif password_verify == password:
        cipher, iv = encrypt(entry, password)

        sys.stdout.write('Username: ')
        username = sys.stdin.readline()[:-1]  # strip \n
        cursor.execute('REPLACE INTO passwords (name, password, iv, username) VALUES (?, ?, ?, ?)', (name, cipher, iv, username))
    else:
        error_and_exit('Passwords do not match')
p_a = p_add


def p_remove(args):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        p_help()
        error_and_exit('$name is a required field')

    cursor.execute('SELECT password, iv FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        password = getpass.getpass('Old: ')
        try:
            if not decrypt(result[0], password, result[1]):
                error_and_exit('Old password is incorrect')
        except ValueError:
            pass
        cursor.execute('DELETE FROM passwords WHERE name = ?', [name])
    else:
        error_and_exit('Password "{0}" was not found'.format(name))
p_r = p_remove


def p_list(args):
    cursor.execute('SELECT name, username FROM passwords')
    rows = []
    name_max = 8
    for row in cursor.fetchall():
        name_max = max(name_max, len(row[0]))
        rows.append(row)
    sys.stdout.write('password' + ' ' * (name_max - 8) + ' | username\n')
    sys.stdout.write('-' * name_max + '-+----------\n')
    for (name, username) in rows:
        sys.stdout.write(name)
        sys.stdout.write(' ' * (name_max - len(name)) + ' |')
        if username:
            sys.stdout.write(' ')
            sys.stdout.write(username)
        sys.stdout.write("\n")
p_l = p_list


def p_merge(args):
    try:
        file = args.pop(0)
    except IndexError:
        file = None

    if not file:
        p_help()
        error_and_exit('$file is a required field')

    if not os.path.exists(file):
        error_and_exit('Could not find {file}'.format(file=file))
    merge_conn = get_connection(file)
    merge_cursor = merge_conn.cursor()
    migrate(merge_cursor)
    merge_cursor.execute('SELECT name, password, iv, username FROM passwords')
    for merge_result in merge_cursor.fetchall():
        name = merge_result[0]
        existing_result = cursor.execute('SELECT username FROM passwords WHERE name = ?', [name]).fetchone()
        if not existing_result:
            print("Adding {name}".format(name=name))
            cursor.execute('INSERT INTO passwords (name, password, iv, username) VALUES (?, ?, ?, ?)', merge_result)
        elif existing_result[0] != merge_result[3]:
            print("Updating {name} username from {0!r} to {1!r}".format(existing_result[0], merge_result[3], name=name))
            cursor.execute('UPDATE passwords SET username = ? WHERE name = ?', [merge_result[3], name])

    merge_cursor.close()
    merge_conn.commit()
p_m = p_merge


def p_check(args):
    master = getpass.getpass('Master: ')
    cursor.execute('SELECT name, password, iv FROM passwords')
    for (name, password, iv) in cursor.fetchall():
        try:
            decrypt(password, master, iv)
        except ValueError:
            print(name)


def p_backup(args):
    try:
        file = args.pop(0)
    except IndexError:
        file = None

    if not file:
        p_help()
        error_and_exit('$file is a required field')

    if os.path.exists(file):
        error_and_exit('Backup file {file} already exists'.format(file=file))

    import shutil
    shutil.copyfile(get_passwords_file(), file)
p_b = p_backup


def p_user(args):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        p_help()
        error_and_exit('$name is a required field')

    cursor.execute('SELECT name FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        sys.stdout.write('Username: ')
        username = sys.stdin.readline()[:-1]  # strip \n
        cursor.execute('UPDATE passwords SET username = ? WHERE name = ?', (username, name))
    else:
        error_and_exit('"{0}" was not found'.format(name))
p_u = p_user


def p_file(args):
    print(get_passwords_file())
p_f = p_file


##|
##|  Run the command
##|
if __name__ == "__main__":
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

    command = locals().get('p_' + command_name)
    if not command:
        command = error_and_exit('Unknown command "{0}"'.format(command_name))
    else:
        try:
            command(args)
        except KeyboardInterrupt:
            sys.stderr.write("Aborting\n")
        cursor.close()
        conn.commit()
