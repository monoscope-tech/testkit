#!/bin/sh
printf 'Name? '
read name
printf 'Hello %s\n' "$name"
printf 'Continue? '
read ok
[ "$ok" = "yes" ] && echo "Done" && exit 0
echo "Aborted"; exit 1
