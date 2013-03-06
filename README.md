 p — Password manager
======================

###### Version 2.0!  Rewritten in Python, using sqlite as the data store.

You'll need the PyCrypto package:

    pip install pycrypto


This little python script stores and retrieves encrypted passwords to a sqlite file.
You can add, remove, and show a single password.

"show" in this case, though, means "copy to clipboard".  The password is never
actually *shown*.  The downside - if you use a clipboard manager, it will be
able to see your passwords.

This is designed to run on Mac OS X, and uses the `pbcopy` and `pbpaste`
commands. If you would like to adapt this to use `xsel`, please fork and
contribute your patch!  <https://github.com/colinta/p>

The default password file is ~/.p_passwords.sql, but this can be changed by
setting the environment variable P_PASSWORDS_FILE before loading p.

Commands
--------

* `p --help` or just `p` - Display the help screen

* `p $entry` — displays the password for the entry, waits, and deletes the
  password after you press enter.

  alias: `p --show`

  ```shell
  $ p bank
  Password:
  The password is in the clipboard
  Press enter to clear the clipboard, or ctrl+c to abort...
  $
  ```

  ...press enter...

* `p --add $entry` — Adds a new entry.

  alias: `p -a`

  ```shell
  $ p --add bank
  The password for "test":
  Master:
  Verify:
  $
  ```

  If the password already exists in the database, you'll need the old password
  to replace it

  ```shell
  $ p --add bank
  The password for "test":
  Old:
  Master:
  Verify:
  $
  ```

* `p --remove` — Removes an entry.  You'll be asked for the password.

  alias: `p -r`

  ```shell
  $ p --remove bank
  Old:
  $
  ```

* `p --list` - Lists the names, does not display any passwords.

  alias `p -l`

  ```shell
  $ p --list
  bank
  test
  $
  ```

* `p --user $entry` - Adds a username to an existing entry.

  alias `p -u`

* `p --file` - Shows the password file location

  alias `p -f`

* `p --merge $file` - Merges entries from another password file. Useful when you
  store your passwords in git, and there's a conflict.

* `p --check` - If you use the same "master" password for all your entries, this
  will make sure that the password can decrypt all the entries.  Any that don't
  decrypt properly will be displayed.

* `p --backup $file` - Copies the password file to a backup.  Will not overwrite
  an existing backup file.

  alias `p -b`

Stdout
------

If the terminal is being redirected, the `--show` command will print the
password.  This is useful when you use `p` in conjunction with, say, the `gist`
command:

    $ git config --global github.password '!p github'
    $ echo 'p varname.nil?' | gist -t rb
    Password:
    https://gist.github.com/4322161

Uses `sys.stdout.isatty()` method to determine whether to prompt or output the
password.
