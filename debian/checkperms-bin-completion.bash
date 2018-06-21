#!/usr/bin/env bash

_checkperms_complete()
{
   local cur prev opts
   COMPREPLY=()
   cur=${COMP_WORDS[COMP_CWORD]}
   prev=${COMP_WORDS[COMP_CWORD-1]}
   opts="-h -v -u -p -m -l -d -y -n -e"

   if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]]; then
      COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
      return 0
   fi

   if [[ ${prev} == "-p" ]]; then
      compopt -o filenames 2>/dev/null
      COMPREPLY=($(compgen -f -- ${cur}))
   elif [[ ${prev} == "-u" ]]; then
      COMPREPLY=($(compgen -u -- ${cur}))
   fi
}

complete -F _checkperms_complete checkperms-bin
