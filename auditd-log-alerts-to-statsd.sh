#!/bin/bash
trap "echo auditd.exited:1|c | nc -u -q0  127.0.0.1 8125" EXIT
tail -F tests/test.log | node auditd_log_alerts.js 2>&1 | while read l; do
  echo $l
  t=$(echo $l | cut -f1 -d":")
  echo "auditd.$t:1|c" | nc -u -q1 127.0.0.1 8125
done
