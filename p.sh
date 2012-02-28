if [[ -z P_PASSWORDS_FILE ]]; then
  P_PASSWORDS_FILE=~/.p_passwords
fi

function p () {
  local cmd

  if [[ ! -f "$P_PASSWORDS_FILE" ]]; then
    echo -n "P_PASSWORDS" > $P_PASSWORDS_FILE
  fi

  if [[ -n "$1" && "${1:0:2}" = "--" ]]; then
    cmd="__p_${1:2}"
    if [[ -z `type -t $cmd` ]]; then
      echo "Unknown command \"p $1\"" >&2
      return 1
    fi

    $cmd "${@:2}"
    return $?
  elif [[ -n "$1" && "${1:0:1}" = "-" ]]; then
    cmd="__p_${1:1}"
    if [[ -z `type -t $cmd` ]]; then
      echo "Unknown command \"p $1\"" >&2
      return 1
    fi

    $cmd "${@:2}"
    return $?
  elif [[ -n "$@" ]]; then
    __p_show "$@"
  else
    __p_help
  fi
}

function __p_help() {
  echo "Commands:"
  echo ""
  echo "--help, -h    Show this message."
  echo "--show \$1    Show the password for \$1.  Default action when \$1 is given."
  echo "--add \$name  Add entry \$name.  You will be prompted for the password."
  echo "--redo        Decrypts and encrypts.  Useful if you want to change the password."
  echo "--all         Shows the entire file (to STDOUT)."
  echo "--set         Sets the passwords file (from STDIN)."
}

function __p_h {
  __p_help "$@"
}


function __p_show {
  local password
  local escaped_name
  local bar_i

  escaped_name="$1"
  escaped_name="${escaped_name//"'"/\'}"  # why, bash, WHY?
  escaped_name=$(python -c "import re ; import sys ; sys.stdout.write(re.escape('$escaped_name'))")
  password=$(openssl enc -d -des3 -a -salt -in "$P_PASSWORDS_FILE" | grep "^$escaped_name|||")

  bar_i=$(indexof "$password" '|||')

  if [[ $bar_i -gt 0 ]]; then
    bar_i=$(($bar_i + 3))
    password="${password:$bar_i}"

    if [[ ! -t 1 ]]; then
      echo -n "$password"
    elif [[ -n `type -t pbpaste` ]]; then
      local clipboard=$(pbpaste)
      echo -n "$password" | pbcopy
      echo -e '\033[1mThe password is in the clipboard\033[0m'
      echo -n 'Press enter to clear the clipboard, or ctrl+c to abort...'
      read
      echo -n "$clipboard" | pbcopy
    elif [[ -n `type -t xsel` ]]; then
      local clipboard=$(xsel -o)
      echo -n "$password" | xsel
      echo -e '\033[1mThe password is in the clipboard\033[0m'
      echo -n 'Press enter to clear the clipboard, or ctrl+c to abort...'
      read
      echo -n "$clipboard" | xsel
    else
      echo -e '\033[1mThe password will be displayed in the clear\033[0m'
      echo -n 'Press enter to continue, or ctrl+c to abort...'
      read
      echo -n -e "$savepos"
      echo "$password"
    fi

  else
    echo "Could not find \"$1\"" >&2
  fi
}


function __p_add {
  local name="$1"
  local escaped_name
  local password
  local passwords
  local nl=$'\n'

  if [[ -z $name ]]; then
    echo -n "What is the name?" >&2
    read name
    echo -n "And the password?" >&2
  else
    echo -n "Name is \"$name\".  And the password?" >&2
  fi
  stty -echo
  read password
  stty echo
  echo ''

  # make sure password does not contain the delimiter
  bar_i=$(indexof "$password" '|||')

  if [[ $bar_i -gt 0 ]]; then
    echo 'Password cannot contain "|||".  It is used delimit "name|||password" in '"$P_PASSWORDS_FILE"
    return 1
  fi

  echo 'You will be asked for your password three times.'
  echo 'Once to decrypt, and twice to re-encrpt.'

  # this command also removes the name, if it is in the file.
  escaped_name="$name"
  escaped_name="${escaped_name//"'"/\'}"  # why, bash, WHY?
  escaped_name=$(python -c "import re ; import sys ; sys.stdout.write(re.escape('$escaped_name'))")
  passwords=$(openssl enc -d -des3 -a -salt -in "$P_PASSWORDS_FILE" | grep -v "^$escaped_name|||")

  # remove final newline if it exists
  passwords="${passwords%%$nl}"
  # and add it right back, along with the new password
  passwords="$passwords$nl$name|||$password$nl"

  echo -n "$passwords" | openssl enc -des3 -a -salt -out "$P_PASSWORDS_FILE"
}

function __p_a {
  __p_add "$@"
}


function __p_remove {
  local password
  local bar_i
  local name="$1"

  if [[ -z $name ]]; then
    echo -n "What is the name?" >&2
    read name
  fi

  # this command removes the name, if it is in the file.
  escaped_name="$name"
  escaped_name="${escaped_name//"'"/\'}"  # why, bash, WHY?
  escaped_name=$(python -c "import re ; import sys ; sys.stdout.write(re.escape('$escaped_name'))")
  passwords=$(openssl enc -d -des3 -a -salt -in "$P_PASSWORDS_FILE" | grep -v "^$escaped_name|||")
  echo -n "$passwords" | openssl enc -des3 -a -salt -out "$P_PASSWORDS_FILE"
}

function __p_r {
  __p_remove "$@"
}


function __p_redo {
  passwords=$(openssl enc -d -des3 -a -salt -in "$P_PASSWORDS_FILE")
  if [[ $? -eq 0 ]]; then
    echo -n "$passwords" | openssl enc -des3 -a -salt -out "$P_PASSWORDS_FILE"
  fi
}


function __p_all {
  openssl enc -d -des3 -a -salt -in "$P_PASSWORDS_FILE"
}


function __p_set {
  openssl enc -des3 -a -salt -out "$P_PASSWORDS_FILE"
}
