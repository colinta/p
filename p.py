#!/usr/bin/env python
"""A password store. Written in python, uses sqlite.

This is designed to run on Mac OS X, and uses the `pbcopy` and `pbpaste`
commands. If you would like to adapt this to use `xsel`, please fork and
contribute your patch!  https://github.com/colinta/p

The default location of the sqlite file is ~/.p_passwords.sql, but you can
set it using the `P_PASSWORDS_FILE` environment variable.

[--show] $name       Show the password for $name and the username if it's
                     available.  Default command.
--verbose, -v $name  Show the password for $name, username, and notes. (enter q
                     to quit)
--pass, -p $name     Show the password for $name, don't show the username.
--help, -h           Show this message.
--add, -a $name      Add entry $name.  You will be prompted for the password.
                     Existing entries will be replaced
--user, -u $name     Add a username to the entry $name.  You will be prompted
                     for the username.
--note $name         Shows the notes for the entry.
--n $name            Add a note to the entry.
--N $name            Clears the note for the entry.
--change, -c $name   Replaces an entry after copying the current password to the
                     clipboard.
--remove, -r $name   Removes an entry
--list, l            Lists all the entry names (no passwords are shown)
--list $filter       Lists entries that include the $filter
--file, f            Show the password file being used
--merge, -m [$file]  Merges entries from another p_password.sql store
--check              Tries to decrypt entries using the "Master" password. Any
                     entries that fail are printed to the screen
--backup, -b $file   Make a backup of the password store
--generate, -g       Generate a password using mouseware
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
    if result < 3:
        migrate_cursor.execute('ALTER TABLE passwords ADD COLUMN note TEXT DEFAULT ""')
        migrate_cursor.execute('INSERT INTO password_migrations (name) VALUES (?)', ['Add note column'])


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


def decrypt(ciphertext, password, iv):
    key = hashlib.sha256(password).digest()
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plaintext_password = decryptor.decrypt(ciphertext).rstrip(chr(0))
    char_regex = re.compile(r'[ -~\n\t]')
    is_char = lambda c: char_regex.match(c)
    if any(not is_char(c) for c in plaintext_password):
        error_and_exit('Wrong!')
    return plaintext_password


def error_and_exit(message):
    sys.stderr.write("\033[1mError: \033[31m{0}\033[0m\n".format(message))
    sys.exit(1)


def p_help(args=[]):
    print(__doc__)
p_h = p_help


def pb_set(content):
    sock = os.popen('pbcopy', 'w')
    sock.write(content)
    sock.close()


def pb_get():
    sock = os.popen('pbpaste', 'r')
    old_board = sock.read()
    sock.close()
    return old_board


def p_pass(args):
    p_show(args, show_username=False)
p_p = p_pass


def p_verbose(args):
    p_show(args, show_username=True, show_notes=True)
p_v = p_verbose


def p_show(args, show_username=True, show_notes=False):
    name = args.pop()
    if not name:
        p_help()
        error_and_exit('$name is a required field')

    cursor.execute('SELECT username, iv, password, note FROM passwords WHERE name = ? LIMIT 1', [name])
    result = cursor.fetchone()
    if result:
        username = result[0]
        iv = result[1]
        cipher_pass = result[2]
        cipher_note = result[3]

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
                sys.stdin.readline()

            sys.stderr.write("\033[1mThe password is in the clipboard\033[0m\n")
            sys.stderr.write('Press enter to restore the clipboard, or ctrl+c to abort...')
            pb_set(plaintext_password)
            sys.stdin.readline()

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

                    quit = sys.stdin.readline()
                    if quit.lower() == "q\n":
                        break

            if pb_get() == plaintext_password:
                pb_set(old_board)
        else:
            sys.stdout.write(plaintext_password)
    else:
        sys.stdout.write('"{0}" was not found.'.format(name))
        rows = search(name)
        if rows:
            sys.stdout.write(' Maybe you meant:\n')
            for row in rows:
                found_name = row[0]
                sys.stdout.write('  {0}\n'.format(found_name))
        sys.stdout.write('\nShould I make an entry? [y]: ')
        should_add = sys.stdin.readline()[:-1]  # strip \n
        if should_add == '' or should_add == 'y':
            p_generate([name])
        else:
            error_and_exit('aborting'.format(name))


def p_generate(args):
    plaintext_password = generate_password()

    old_board = pb_get()
    pb_set(plaintext_password)

    sys.stderr.write("\033[1mThe password is in the clipboard\033[0m\n")
    sys.stderr.write('Press enter to clear the clipboard, or ctrl+c to abort...')
    sys.stdin.readline()

    if pb_get() == plaintext_password:
        pb_set(old_board)
p_g = p_generate


def p_add(args, plaintext_password=None):
    try:
        name = args.pop(0)
    except IndexError:
        name = None

    if not name:
        p_help()
        error_and_exit('$name is a required field')

    if not plaintext_password:
        sys.stderr.write('Enter the password for "{0}"\n'.format(name))
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
            sys.stdout.write('Keep using {!r}: [Yn] '.format(username))
            keep_it = sys.stdin.readline()[:-1]
            if keep_it.lower() == "n":
                username = None

        if not username:
            sys.stdout.write('Username: ')
            username = sys.stdin.readline()[:-1]  # strip \n

        cursor.execute('REPLACE INTO passwords (name, password, iv, username) VALUES (?, ?, ?, ?)', (name, cipher, iv, username))
    else:
        error_and_exit('Passwords do not match')
p_a = p_add


def p_change(args):
    p_show(args[:])
    p_generate(args[:])
p_c = p_change


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


def search(p_filter):
    cursor.execute('SELECT name, username, note FROM passwords')

    rows = []
    for row in cursor.fetchall():
        name, username, note = row

        if p_filter:
            try:
                name.index(p_filter)
                include = True
            except ValueError:
                include = False
        else:
            include = True

        if include:
            rows.append(row)
    return rows


def p_list(args):
    try:
        p_filter = args.pop(0)
    except IndexError:
        p_filter = None

    rows = search(p_filter)
    name_max = 8
    username_max = 8
    for row in rows:
        name, username, note = row
        name_max = max(name_max, len(name))
        username_max = max(username_max, len(username))

    sys.stdout.write('password' + ' ' * (name_max - 8) + ' | username' + ' ' * (username_max - 8) + ' | note?\n')
    sys.stdout.write('-' * name_max + '-+-' + '-' * username_max + '-+-------\n')
    for (name, username, note) in rows:
        sys.stdout.write(name)
        sys.stdout.write(' ' * (name_max - len(name)) + ' | ')
        if username:
            sys.stdout.write(username)
            sys.stdout.write(' ' * (username_max - len(username)) + ' |')
        else:
            sys.stdout.write(' ' * username_max + ' |')

        if note:
            sys.stdout.write(' (encrypted)')
        sys.stdout.write("\n")
p_l = p_list


def confirm(prompt, default=''):
    sys.stderr.write(prompt)
    sys.stderr.write(" [yn] ".replace(default, default.upper()))
    yay_nay = sys.stdin.readline()[:-1]  # strip \n
    if not yay_nay:
        yay_nay = default
    return yay_nay.lower() == 'y'

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
            if confirm("Add {name}?".format(name=name)):
                cursor.execute('INSERT INTO passwords (name, password, iv, username) VALUES (?, ?, ?, ?)', merge_result)
        elif existing_result[0] != merge_result[3]:
            prompt = "Update {name} username from {0!r} to {1!r}?".format(existing_result[0], merge_result[3], name=name)
            if confirm(prompt):
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


def p_note(args):
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
            sys.stdout.write("\n")
    else:
        error_and_exit('No entry for {!r}'.format(name))


def p_add_note(args):
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
            sys.stdout.write(prompt)
            line = sys.stdin.readline()[:-1]  # strip \n
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
p_n = p_add_note


def p_clear_note(args):
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
p_N = p_clear_note


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
            command_name = sys.argv[1][2:].replace('-', '_')
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
