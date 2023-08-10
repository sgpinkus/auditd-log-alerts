#!/bin/bash
tmp=$(mktemp -d)
trap "rm -rf $tmp" EXIT
cd "$tmp"
cp /usr/share/doc/auditd/examples/rules/{10-base-config.rules,30-stig.rules,32-power-abuse.rules,42-injection.rules,43-module-load.rules,99-finalize.rules} .
cat /usr/share/doc/auditd/examples/rules/31-privileged.rules | sed -r 's/^#//' | sed -r 's/priv.rules/31-privileged.rules/' > 31-privileged.rules.script
/bin/bash 31-privileged.rules.script
for i in *.rules; do
 echo "# ${i}"
  cat "${i}" | egrep -v "^#" | egrep -v "^$"
done
