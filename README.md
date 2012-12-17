 p — Password manager
======================

###### Version 2.0!  Rewritten in Python, using sqlite as the data store.

You'll need the PyCrypto package:

    pip install pycrypto


This little python script stores and retrieves encrypted passwords to a sqlite file.
You can add, remove, and show a single password.

"show" in this case, though, means "copy to clipboard".  The password is never
actually *shown*.  The downside - if you use a clipboard manager, it will be
able to see your passwords.  I'd recommend against using this in that case.

The default location is ~/.p_passwords.sql, but this can be changed by setting
the environment variable P_PASSWORDS_FILE before loading p.

Commands
--------

* `p [entry]` — displays the password for the entry, waits, and deletes the password after you press enter
  alias: `p --show`

  ```shell
  $ p bank
  Password:
  The password is in the clipboard
  Press enter to clear the clipboard, or ctrl+c to abort...
  $
  ```

  ...press enter...

* `p --add [entry]` — Adds a new entry.
  alias: `p -a`

  ```shell
  $ p --add bank
  The password for "test":
  Master:
  Verify:
  $
  ```

  If the password already exists in the database, you'll need the old password to replace it

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
