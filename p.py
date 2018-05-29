#!/usr/bin/env python
"""A password store. Written in python, uses sqlite.

This is designed to run on Mac OS X, and uses the `pbcopy` and `pbpaste`
commands. If you would like to adapt this to use `xsel`, please fork and
contribute your patch!  https://github.com/colinta/p

The default location of the sqlite file is ~/.p_passwords.sql, but you can
set it using the `P_PASSWORDS_FILE` environment variable.

[--show] $name       Show the password for $name and the username if it's
                     available.  Default command.  If there is no entry with
                     this name, a password can be created (using --create)
--verbose, -v $name  Show the password for $name, username, and notes. (enter q to quit)
--pass, -p $name     Show the password for $name, don't show the username.
--help, -h           Show this message.
--rename $old $new   Rename an entry
--add, -a $name      Add entry $name.  You will be prompted for the password. Existing entries will be replaced
--user, -u $name     Add a username to the entry $name.  You will be prompted for the username.
--note $name         Shows the notes for the entry.
--n $name            Add a note to the entry.
--N $name            Clears the note for the entry.
--change, -c $name   Replaces an entry after copying the current password to the clipboard.
--remove, -r $name   Removes an entry
--list, l            Lists all the entry names (no passwords are shown)
--list $filter       Lists entries that include the $filter
--file, f            Show the password file being used
--merge, -m [$file]  Merges entries from another p_password.sql store
--check              Tries to decrypt entries using the "Master" password. Any entries that fail are printed to the screen.
--backup, -b $file   Make a backup of the password store
--generate, -g       Generate a password using mouseware
--create, -c $name   Generate a password and save it to $name
"""
import sqlite3
import os
import sys
import getpass
import hashlib
import random
import re
import mouseware


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


def await_enter():
    sys.stdin.readline()


def get_input():
    return sys.stdin.readline()[:-1]  # strip \n


def generate_password():
    return mouseware.generate()


def migrate(migrate_cursor):
    migrate_cursor.execute('''CREATE TABLE
                        IF NOT EXISTS
                        password_migrations
                      (
                        version INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT
                      )''')

    migrate_cursor.execute('SELECT COUNT(*) FROM password_migrations')
    result = migrate_cursor.fetchone()[0] or 0
    if result < 1:
        desc = 'Initial commit'
        sys.stderr.write("Migrating to version 1: {}\n".format(desc))
        migrate_cursor.execute('CREATE TABLE IF NOT EXISTS passwords (name TEXT PRIMARY KEY, password TEXT, iv TEXT)')
        migrate_cursor.execute('INSERT INTO password_migrations (name) VALUES (?)', [desc])
    if result < 2:
        desc = 'Add username column'
        sys.stderr.write("Migrating to version 2: {}\n".format(desc))
        migrate_cursor.execute('ALTER TABLE passwords ADD COLUMN username TEXT DEFAULT ""')
        migrate_cursor.execute('INSERT INTO password_migrations (name) VALUES (?)', [desc])
    if result < 3:
        desc = 'Add note column'
        sys.stderr.write("Migrating to version 3: {}\n".format(desc))
        migrate_cursor.execute('ALTER TABLE passwords ADD COLUMN note TEXT DEFAULT ""')
        migrate_cursor.execute('INSERT INTO password_migrations (name) VALUES (?)', [desc])
    if result < 4:
        desc = 'Add note column'
        sys.stderr.write("Migrating to version 4: {}\n".format(desc))
        migrate_cursor.execute('ALTER TABLE passwords ADD COLUMN count INT DEFAULT 0')
        migrate_cursor.execute('INSERT INTO password_migrations (name) VALUES (?)', [desc])


conn = get_default_connection()
cursor = conn.cursor()
migrate(cursor)


def encrypt(entry, password, iv=None):
    if not iv:
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    key = hashlib.sha256(password).digest()
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    while len(entry) % 16 > 0:
        entry += chr(0)
    return encryptor.encrypt(entry), iv


def decrypt(ciphertext, password, iv, exit=True):
    key = hashlib.sha256(password).digest()
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plaintext_password = decryptor.decrypt(ciphertext).rstrip(chr(0))
    char_regex = re.compile(r'[ -~\n\t]')
    is_char = lambda c: char_regex.match(c)
    if any(not is_char(c) for c in plaintext_password):
        if exit:
            error_and_exit('Wrong!')
        else:
            return None
    return plaintext_password


def error_and_exit(message):
    sys.stderr.write("\033[1mError: \033[31m{}\033[0m\n".format(message))
    sys.exit(1)


def just_exit(message=None):
    if message:
        sys.stderr.write("\033[31m{}\033[0m\n".format(message))
    sys.exit(1)


##|
##| COMMANDS
##|
COMMANDS = {}

def command_help(args=[]):
    print(__doc__)
COMMANDS['h'] = command_help
COMMANDS['help'] = command_help


_pb_prev = None
def pb_prev():
    return _pb_prev

def pb_set(content):
    global _pb_prev
    sock = os.popen('pbcopy', 'w')
    sock.write(content)
    _pb_prev = content
    sock.close()


def pb_get():
    sock = os.popen('pbpaste', 'r')
    old_board = sock.read()
    sock.close()
    return old_board
_pb_prev = pb_get()


def command_migrations(args):
    cursor.execute('SELECT version, name FROM password_migrations ORDER BY version')
    for row in cursor.fetchall():
        version, name = row
        print(str(version) + ": " + name)
COMMANDS['migrations'] = command_migrations

def command_password_only(args):
    command_show(args, show_username=False)
COMMANDS['p'] = command_password_only
COMMANDS['pass'] = command_password_only


def command_verbose(args):
    command_show(args, show_username=True, show_notes=True)
COMMANDS['v'] = command_verbose
COMMANDS['verbose'] = command_verbose


def command_show(args, show_username=True, show_notes=False):
    name = args.pop()
    if not name:
        command_help()
        error_and_exit('$name is a required field')

    cursor.execute('SELECT username, iv, password, note, count FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        username = result[0]
        iv = result[1]
        cipher_pass = result[2]
        cipher_note = result[3]
        count = result[4]
        cursor.execute('UPDATE passwords SET count = ? WHERE name = ?', [count + 1, name])

        password = getpass.getpass()
        plaintext_password = decrypt(cipher_pass, password, iv)
        plaintext_note = cipher_note and decrypt(cipher_note, password, iv)

        if sys.stdout.isatty():
            old_board = pb_get()

            if show_username and username:
                sys.stderr.write("\033[1mThe username is in the clipboard\033[0m\n")
                sys.stderr.write("\033[1mUsername:\033[0m ")
                sys.stderr.write(username)
                sys.stderr.write("\n")
                sys.stderr.write('Press enter to copy the password, or ctrl+c to abort...')
                pb_set(username)
                await_enter()

            sys.stderr.write("\033[1mThe password is in the clipboard\033[0m\n")
            sys.stderr.write('Press enter to restore the clipboard, or ctrl+c to abort...')
            pb_set(plaintext_password)
            await_enter()

            if show_notes and plaintext_note:
                sys.stderr.write("\033[1mNotes: (enter 'q' to abort)\033[0m\n")
                notes = plaintext_note.split("\n")
                for note in notes:
                    if ':' in note:
                        note = note.split(':')
                        key = note[0].strip()
                        value = note[1].strip()
                        sys.stderr.write("{} ({!r}) is in the clipboard...".format(key, value))
                        pb_set(value)
                    else:
                        sys.stderr.write("{!r} is in the clipboard...".format(note))
                        pb_set(note)

                    quit = get_input()
                    if quit.lower() == "q":
                        break

            if pb_get() == pb_prev():
                pb_set(old_board)
        else:
            sys.stdout.write(plaintext_password)
    else:
        sys.stderr.write('{!r} was not found.\n'.format(name))
        rows = search(name)
        if rows:
            for row in rows:
                found_name = row[0]
                if confirm('Did you mean {!r}?'.format(found_name), 'y'):
                    return command_show([found_name])

        if confirm('Should I make an entry?', 'y'):
            command_create([name])
        else:
            just_exit()
COMMANDS['show'] = command_show

def command_create(args):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        command_help()
        error_and_exit('$name is a required field')

    plaintext_password = generate_password()
    command_add([name], plaintext_password)

    old_board = pb_get()
    pb_set(plaintext_password)
    sys.stderr.write("\033[1mThe password is in the clipboard\033[0m\n")
    sys.stderr.write('Press enter to clear the clipboard, or ctrl+c to abort...')
    await_enter()

    if pb_get() == pb_prev():
        pb_set(old_board)
COMMANDS['c'] = command_create
COMMANDS['create'] = command_create


def command_generate(args):
    plaintext_password = generate_password()

    old_board = pb_get()
    pb_set(plaintext_password)

    sys.stderr.write("\033[1mThe password is in the clipboard\033[0m\n")
    sys.stderr.write('Press enter to clear the clipboard, or ctrl+c to abort...')
    await_enter()

    if pb_get() == pb_prev():
        pb_set(old_board)
COMMANDS['g'] = command_generate
COMMANDS['generate'] = command_generate

def command_rename(args):
    try:
        old_name = args.pop(0)
        new_name = args.pop(0)
    except IndexError:
        old_name = None
        new_name = None

    if not (old_name and new_name):
        error_and_exit('$old_name $new_name are required fields')

    cursor.execute('SELECT name FROM passwords WHERE name = ? LIMIT 1', [old_name])
    result = cursor.fetchone()
    if result:
        cursor.execute('UPDATE passwords SET name = ? WHERE name = ? LIMIT 1', [new_name, old_name])
        sys.stderr.write("Renamed {!r} to {!r}\n".format(old_name, new_name))
    else:
        error_and_exit('No entry for {!r}'.format(old_name))
COMMANDS['rename'] = command_rename

def command_add(args, plaintext_password=None):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        command_help()
        error_and_exit('$name is a required field')

    if not plaintext_password:
        sys.stderr.write('Enter the password for {!r}\n'.format(name))
        plaintext_password = getpass.getpass('or leave blank for more options: ')
        if not plaintext_password:
            if confirm('Use clipboard?', 'y'):
                plaintext_password = pb_get().strip()
            else:
                sys.stderr.write('Password generated\n')
                plaintext_password = generate_password()

    cursor.execute('SELECT username, password, iv FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    username = None
    if result:
        username = result[0]
        password = getpass.getpass('Old: ')
        try:
            if not decrypt(result[1], password, result[2]):
                error_and_exit('Old password is incorrect')
        except ValueError:
            pass

    password = getpass.getpass('Master: ')
    password_verify = getpass.getpass('Verify: ')

    if password == '':
        error_and_exit('Password must not be blank')
    elif password_verify == password:
        cipher, iv = encrypt(plaintext_password, password)

        if username:
            sys.stderr.write('Keep using {!r}: [Yn] '.format(username))
            keep_it = get_input()
            if keep_it.lower() == "n":
                username = None

        if not username:
            sys.stderr.write('Username: ')
            username = get_input()

        cursor.execute('REPLACE INTO passwords (name, password, iv, username) VALUES (?, ?, ?, ?)', (name, cipher, iv, username))
    else:
        error_and_exit('Passwords do not match')
COMMANDS['a'] = command_add
COMMANDS['add'] = command_add


def command_change(args):
    command_show(args[:])
    command_generate(args[:])
COMMANDS['c'] = command_change
COMMANDS['change'] = command_change


def command_remove(args):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        command_help()
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
        error_and_exit('No entry for {!r}'.format(name))
COMMANDS['r'] = command_remove
COMMANDS['remove'] = command_remove


def search(filter):
    cursor.execute('SELECT name, username, note, count FROM passwords ORDER BY count DESC')

    rows = []
    for row in cursor.fetchall():
        name, username, note, count = row

        if filter:
            try:
                name.index(filter)
                include = True
            except ValueError:
                include = False
        else:
            include = True

        if include:
            rows.append(row)
    return rows


def command_list(args):
    try:
        filter = args.pop(0)
    except IndexError:
        filter = None

    rows = search(filter)
    name_max = 8
    username_max = 8
    for row in rows:
        name, username, _, _ = row
        name_max = max(name_max, len(name))
        username_max = max(username_max, len(username))

    sys.stdout.write('name' + ' ' * (name_max - 4) + ' | username' + ' ' * (username_max - 8) + ' | note? | count\n')
    sys.stdout.write('-' * name_max + '-+-' + '-' * username_max + '-+-------+-----\n')
    for (name, username, note, count) in rows:
        sys.stdout.write(name)
        sys.stdout.write(' ' * (name_max - len(name)) + ' | ')
        if username:
            sys.stdout.write(username)
            sys.stdout.write(' ' * (username_max - len(username)) + ' |')
        else:
            sys.stdout.write(' ' * username_max + ' |')

        if note:
            sys.stdout.write('  YES ')
        else:
            sys.stdout.write('      ')

        if count > 9999:
            sys.stdout.write(' | 10k+')
        else:
            sys.stdout.write(' | %4d' % (count))
        sys.stdout.write("\n")
COMMANDS['l'] = command_list
COMMANDS['list'] = command_list


def confirm(prompt, default=''):
    sys.stderr.write(prompt)
    sys.stderr.write(" [yn] ".replace(default, default.upper()))
    yay_nay = get_input()
    if not yay_nay:
        yay_nay = default
    return yay_nay.lower() == 'y'

def command_merge(args):
    try:
        file = args.pop(0)
    except IndexError:
        file = None

    if not file:
        command_help()
        error_and_exit('$file is a required field')

    if not os.path.exists(file):
        error_and_exit('Could not find {!r}'.format(file))

    password = getpass.getpass('Password: ')

    merge_conn = get_connection(file)
    merge_cursor = merge_conn.cursor()
    migrate(merge_cursor)
    merge_cursor.execute('SELECT name, password, iv, username FROM passwords')
    for merge_result in merge_cursor.fetchall():
        name = merge_result[0]
        existing_result = cursor.execute('SELECT name, password, iv, username FROM passwords WHERE name = ?', [name]).fetchone()
        if not existing_result:
            if confirm("Add {name}?".format(name=name)):
                cursor.execute('INSERT INTO passwords (name, password, iv, username) VALUES (?, ?, ?, ?)', merge_result)
        else:
            if existing_result[3] != merge_result[3]:
                prompt = "Update {name} username from {0!r} to {1!r}?".format(existing_result[0], merge_result[3], name=name)
                if confirm(prompt):
                    cursor.execute('UPDATE passwords SET username = ? WHERE name = ?', [merge_result[3], name])

            (merge_password, merge_iv) = (merge_result[1], merge_result[2])
            (existing_password, existing_iv) = (existing_result[1], existing_result[2])
            plaintext_merge = decrypt(merge_password, password, merge_iv)
            plaintext_existing = decrypt(existing_password, password, existing_iv)
            if plaintext_merge and plaintext_existing and plaintext_merge != plaintext_existing:
                prompt = "Update {name} password from {0!r} to {1!r}?".format(plaintext_existing, plaintext_merge, name=name)
                if confirm(prompt):
                    cursor.execute('UPDATE passwords SET password = ?, iv = ? WHERE name = ?', [merge_password, merge_iv, name])

    merge_cursor.close()
    merge_conn.commit()
COMMANDS['m'] = command_merge
COMMANDS['merge'] = command_merge


def command_check(args):
    master = getpass.getpass('Master: ')
    cursor.execute('SELECT name, password, iv FROM passwords')
    for (name, password, iv) in cursor.fetchall():
        try:
            decrypt(password, master, iv)
        except ValueError:
            print(name)

COMMANDS['check'] = command_check

def command_backup(args):
    try:
        file = args.pop(0)
    except IndexError:
        file = None

    if not file:
        command_help()
        error_and_exit('$file is a required field')

    if os.path.exists(file):
        error_and_exit('Backup file {!r} already exists'.format(file))

    import shutil
    shutil.copyfile(get_passwords_file(), file)
COMMANDS['b'] = command_backup
COMMANDS['backup'] = command_backup


def command_user(args):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        command_help()
        error_and_exit('$name is a required field')

    cursor.execute('SELECT name FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        sys.stderr.write('Username: ')
        username = get_input()
        cursor.execute('UPDATE passwords SET username = ? WHERE name = ?', (username, name))
    else:
        error_and_exit('No entry for {!r}'.format(name))
COMMANDS['u'] = command_user
COMMANDS['user'] = command_user


def command_note(args):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        error_and_exit('$name is a required field')

    cursor.execute('SELECT note, iv FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        cipher_pass = result[0]
        if not cipher_pass:
            error_and_exit('No note for {!r}'.format(name))
        else:
            iv = result[1]

            password = getpass.getpass()
            plaintext_note = decrypt(cipher_pass, password, iv)
            sys.stdout.write(plaintext_note)
            sys.stderr.write("\n")
    else:
        error_and_exit('No entry for {!r}'.format(name))

COMMANDS['note'] = command_note

def command_add_note(args):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    try:
        note = args.pop(0)
    except IndexError:
        note = ''
        line = True
        prompt = 'New note: '
        while line:
            sys.stderr.write(prompt)
            line = get_input()
            prompt = '........> '
            if line:
                if note:
                    note += "\n"
                note += line

    if not name:
        error_and_exit('$name is a required field')

    cursor.execute('SELECT note, iv FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        cipher_pass = result[0]
        iv = result[1]
        password = getpass.getpass()
        plaintext_note = decrypt(cipher_pass, password, iv)
        if plaintext_note:
            plaintext_note += "\n"
        plaintext_note += note
        encrypted_note, iv = encrypt(plaintext_note, password, iv)
        cursor.execute('UPDATE passwords SET note = ? WHERE name = ?', [encrypted_note, name])
        sys.stderr.write("Note updated\n")
    else:
        error_and_exit('No entry for {!r}'.format(name))
COMMANDS['n'] = command_add_note
COMMANDS['add_note'] = command_add_note


def command_clear_note(args):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        error_and_exit('$name is a required field')

    cursor.execute('SELECT password, iv, note FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        cipher_pass = result[0]
        iv = result[1]
        note = result[2]
        if note:
            password = getpass.getpass()
            decrypt(cipher_pass, password, iv)
            cursor.execute('UPDATE passwords SET note = ? WHERE name = ?', ['', name])
            sys.stderr.write('Note removed\n')
        else:
            sys.stderr.write('Entry {!r} doesn\'t have a note.\n'.format(name))
    else:
        error_and_exit('No entry for {!r}'.format(name))
COMMANDS['N'] = command_clear_note
COMMANDS['clear_note'] = command_clear_note


def command_file(args):
    print(get_passwords_file())
COMMANDS['f'] = command_file
COMMANDS['file'] = command_file


##|
##|  Run the command
##|
if __name__ == "__main__":
    if len(sys.argv) == 1:
        command_name = 'help'
        args = []
    else:
        if sys.argv[1][0:2] == '--':
            command_name = sys.argv[1][2:].replace('-', '_')
            args = sys.argv[2:]
        elif sys.argv[1][0] == '-':
            command_name = sys.argv[1][1:]
            args = sys.argv[2:]
        else:
            command_name = 'show'
            args = sys.argv[1:]

    try:
        command = COMMANDS[command_name]
    except KeyError:
        cursor.close()
        conn.commit()
        error_and_exit('Unknown command {!r}'.format(command_name))

    try:
        command(args)
    except KeyboardInterrupt:
        sys.stderr.write("Aborting\n")
    cursor.close()
    conn.commit()
