# SIMPLE AUDITD LOG ALERTS
The script [auditd_log_alerts.js](./auditd_log_alerts.js) is a minimal NodeJS 12.x script that takes an `auditd.log` on stdin and filters it to zero or more security alert messages. Can work by simply tailing an `auditd.log`, or installed as an audisp plugin. "Alerts" are just any event that make it through the hardcoded filter rules. Alerts have a (baked in) level of severity from 0 (highest) to 7 (mirroring syslog levels). Alert messages are fairly rudimentary digest of the raw auditd events.

What's considered an noteworthy event is based heavily on a review of the open source `audisp-prelude` audisp plugin that came with [auditd-2.8.x][audit_src], and the [STIG][stig] and other rule sets that come packaged with auditd. This script is less sophisticated than `audisp-prelude` but is also much simpler to use (I tried and failed to get prelude working, hence this).

# USAGE
Script can be used as is *as a script*, printing text messages on stdout:

        tail -F auditd.log | node auditd_log_alerts.js

or imported *as a module* providing objects (`{ msg, level }`) to caller given log lines. See this [AWS Cloudwatch lambda handler](docs/cloudwatch_reader.skel.js) example, or C&P default console logger from the script and modify to suit.

# ANALYSIS AND DESIGN
Main requirements and constraints:

  - Single simple script file no config necessary for useful deploy.
  - Report on close to same events as `audisp-prelude` plugin, plus STIG and other watches.
  - No support for correlation.
  - Work as a `audisp` plugin and just like `tail -F audit.log | auditd_log_alerts.js`. It turns out there is very little difference, but as a plugin is theoretically more secure.

# NOTES

## SETTING UP AUDITD
Make /etc/audit/rules.d look something like:

        /etc/audit/rules.d/
        ├── 10-base-config.rules
        ├── 30-stig.rules
        ├── 31-privileged.rules
        ├── 32-power-abuse.rules
        ├── 42-injection.rules
        ├── 43-module-load.rules
        └── 99-finalize.rules

[audit_src]: http://deb.debian.org/debian/pool/main/a/audit/audit_2.8.4.orig.tar.gz
[stig]: https://docs.bmc.com/docs/discovery/111/stig-rules-for-rhel6-met-using-compliance-script-669206959.html#STIGrulesforRHEL6metusingcompliancescript-STIGrulesforauditing
