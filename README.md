 p.sh — Password manager
=========================

This little bash script stores and retrieves passwords to an encrypted passwords file.
You can add, remove, and show a single password, or list all of them.

The default location is ~/.p_passwords, but this can be changed by setting P_PASSWORDS_FILE
before loading p.sh.

Commands
--------

* `p [entry]` — displays the password for the entry, waits, and deletes the password after you press enter

  ```shell
  $ p bank
  enter des-ede3-cbc decryption password:
  abcd1234
  ```

  ...press enter...

  ```shell
  $ p bank
  enter des-ede3-cbc decryption password:
  $ # the password gets removed (I'm using bash's \033[s and \033[u escape sequences)
  ```

  If you want the password to "hang around", you can pipe the output.

  ```shell
  $ p bank | grep .
  enter des-ede3-cbc decryption password:
  abcd1234
  $
  ```

* `p --add [entry]` — Adds a new entry.  This requires the entire file to be re-encrypted.  Anyone know a way around that?
  alias: `p -a`

  ```shell
  $ p --add bank
  Name is "test".  And the password? [not shown]
  You will be asked for your password three times.
  Once to decrypt, and twice to re-encrpt.
  enter des-ede3-cbc decryption password:
  enter des-ede3-cbc encryption password:
  Verifying - enter des-ede3-cbc encryption password:
  ```

  I would love to somehow append the encrypted contents.

* `p --remove` — Removes an entry.  This requires the entire file to be re-encrypted.
  alias: `p -r`

* `p --recrypt` — Decrypts and encrypts.  So you can change the filename.

* `p --all` — displays the P_PASSWORDS_FILE.

* **CAREFUL** `p --set` — writes stdin to the P_PASSWORDS_FILE.  This resets the passwords file, so DON'T USE THIS COMMAND! :-)
