#!/usr/bin/env node
/**
 * Very simple online audit.log alert filter / parser. Use in production at own peril. Alerts are
 * based off roughly looking at what audisp-prelude reports on (reports are simpler). Known keyed
 * syscalls are based on audit usr/share rule sets.
 * You can import symbols from this file and use (see cloudwatch_reader.js). This file also includes
 * a convenience parser that read from stdin and prints to stdout. Use like:
 * `tail -F audit.log | auditd_log_alerts.js` or as audisp plugin. Use these env vars:
 *   AUDITD_LOG_ALERTS_STDOUT_LOGFMT=custom # or logfmt
 *   AUDITD_LOG_ALERTS_STDOUT_LEVEL=notice
 */

// Alert levels follow syslog levels.
const levels = {
  emerg: 0,
  alert: 1,
  crit: 2,
  error: 3,
  warning: 4,
  notice: 5,
  info: 6,
  debug: 7,
};
const levelNames = Object.fromEntries(Object.entries(levels).map(k => [k[1], k[0]]));
// Used in mapping event types to field to print.
// TODO: Needs refinement esp rel different types of watches.
const commonFields = ['node', 'type', '_id'];
const userFields = ['uid', 'UID', 'auid', 'AUID'];
const loginFields = ['ses', 'acct', 'exe', 'terminal', 'addr', 'hostname', 'res'];
const sysCallFields = ['ses', 'syscall', 'SYSCALL', 'exe', 'pid', 'proctitle', 'success', 'tty', 'key'];
const fileInfoFields = ['cwd-cwd', 'path-name', 'path-mode'];
// Description for syscall watches.  Also serves as list of syscalls to report on - all else ignored.
const stigWatchMessages = {
  'access': 'Unauthorized access attempts to files (unsuccessful)',
  'actions': 'Sudo system administration action',
  'code-injection': 'Code injection (ptrace)',
  'data-injection': 'Data injection (ptrace)',
  'delete': 'File deleted by the user',
  'export': 'Media mounted',
  'identity': 'Identity database file action',
  'MAC-policy': 'Possible MAC policy effect',
  'module-load': 'Kernel module load',
  'modules': 'Kernel module operation',
  'module-unload': 'Kernel module unload',
  'perm_mod': 'Discretionary access control permission modification',
  'power-abuse': 'Admin may be abusing power',
  'privileged': 'Attempt to execute privileged program',
  'register-injection': 'Register injection (ptrace)',
  'system-locale': 'Operation that may effect system locale',
  'time-change': 'Operation that may effect system time',
  'tracing': 'Execution of ptrace',
};
const stigWatchLevels = (e = {}) => {
  if (e.key === 'time-change' && e.syscall === '159' && e.success === 'yes') return levels.debug; // adjtimex - apparently this can happen alot on some systems.
  if (e.key === 'perm_mod' && e.success === 'yes') return levels.info;
  if (e.key === 'delete' && e.success === 'yes' && /^\/tmp\//.test(e['path-name'])) return levels.debug;
  if (e.key === 'delete' && e.success === 'yes') return levels.info
  if (e.key === 'access' && !/^\/(etc|home)\//.test(e['path-name'])) return levels.notice; // Failure access some file is also extremely noisy unfortunately.
  if (e.success !== 'yes') return levels.error;
  return levels.warning;
};
/**
 * Hardcoded list of things we want to watch for, plus a natural lang desc of what they mean and keys
 * to print with the alert. The level is a advisory and may not be a very good indication of severity.
 * There are many more auditd events - see ausearch -m
 */
const watchedEventSpecs = [
  {
    match: e => ['DAEMON_ERR', 'DAEMON_ABORT'].includes(e.type),
    desc: 'Auditd Daemon Error',
    fields: [...commonFields, 'res'],
    level: levels.error,
  },
  {
    match: e => e.type === 'USER_LOGIN',
    desc: 'User Login',
    fields: [...commonFields, ...userFields, ...loginFields],
    level: e => (e.res === 'failed' ? levels.notice : levels.warning),
  },
  {
    match: e => e.type === 'USER_START' && e.uid === '0' && e.auid !== '0',
    desc: 'User Session Start',
    fields: [...commonFields, ...userFields, ...loginFields],
    level: levels.notice,
  },
  {
    match: e => e.type === 'ANOM_LOGIN_FAILURES',
    desc: 'Max Failed Logins',
    fields: [...commonFields, ...userFields, ...loginFields],
    level: levels.warning,
  },
  {
    match: e => e.type === 'ANOM_LOGIN_SESSIONS',
    desc: 'Max Concurrent Sessions',
    fields: [...commonFields, ...userFields, ...loginFields],
    level: levels.warning,
  },
  {
    match: e => e.type === 'ANOM_LOGIN_LOCATION',
    desc: 'Login From Forbidden Location',
    fields: [...commonFields, ...userFields, ...loginFields],
    level: levels.warning,
  },
  {
    match: e => e.type === 'ANOM_LOGIN_TIME',
    desc: 'Login During Forbidden Time',
    fields: [...commonFields, ...userFields, ...loginFields],
    level: levels.warning,
  },
  {
    match: e => e.type === 'AUDIT_AVC' || e.type === 'USER_AVC',
    desc: 'SELinux Access Vector Cache (AVC) Event',
    fields: [...commonFields, ...fileInfoFields],
    level: levels.alert,
  },
  {
    match: e => e.type === 'ANOM_ABEND',
    desc: 'Abnormal Termination of Program',
    fields: [...commonFields, ...userFields, ...fileInfoFields, 'sig'],
    level: levels.alert,
  },
  {
    match: e => e.type === 'ANOM_PROMISCUOUS' && e.prom === '256' && e.old_prom === '0',
    desc: 'Promiscuous Socket Opened',
    fields: [...commonFields, ...userFields, 'dev', 'prom'],
    level: e => ((/^veth/).test(e.dev) ? levels.debug : levels.alert),
  },
  {
    match: e => e.type === 'ANOM_PROMISCUOUS' && e.prom === '0' && e.old_prom === '256',
    desc: 'Promiscuous Socket Closed',
    fields: [...commonFields, ...userFields, 'dev', 'prom'],
    level: e => ((/^veth/).test(e.dev) ? levels.debug : levels.info),
  },
  {
    match: e => e.type === 'ANOM_PROMISCUOUS',
    desc: 'Promiscuous Socket Changed',
    fields: [...commonFields, ...userFields, 'dev', 'prom', 'old_prom'],
    level: e => ((/^veth/).test(e.dev) ? levels.debug : levels.info),
  },
  {
    match: e => e.type === 'MAC_STATUS' && e.enforcing === '0' && e.old_enforcing === '1',
    desc: 'SE Linux Enforcement Disabled',
    fields: [...commonFields, ...userFields, 'enforcing'],
    level: levels.alert,
  },
  {
    match: e => e.type === 'MAC_STATUS' && e.enforcing === '1' && e.old_enforcing === '0',
    desc: 'SE Linux Enforcement Enabled',
    fields: [...commonFields, ...userFields, 'enforcing'],
    level: levels.info,
  },
  {
    match: e => e.type === 'MAC_STATUS',
    desc: 'SE Linux Enforcement Changed',
    fields: [...commonFields, ...userFields, 'enforcing'],
    level: levels.info,
  },
  {
    match: e => e.type === 'TTY',
    desc: 'Input on Administrative TTY',
    fields: [...commonFields, ...userFields, 'tty'],
    level: levels.warning,
  },
  {
    match: e => e.type === 'GRP_AUTH' && 'res' in e && e.res === 'failure',
    desc: 'Group Login Failure',
    fields: [...commonFields, ...userFields, 'new-gid'],
    level: levels.alert,
  },
  {
    match: e => e.type === 'SYSCALL' && stigWatchMessages[e.key],
    desc: e => stigWatchMessages[e.key],
    fields: [...commonFields, ...userFields, ...sysCallFields, ...fileInfoFields],
    level: stigWatchLevels,
  },
];


/**
 * Take a series of raw log lines and convert them to event objects. This may entail merging lines belonging to the
 * same logical event.
 * @returns object representing an auditd event with fields lower cased and flattened.
 */
function linesToEvents(lines) {
  let currentEvent;
  const events = [];
  let suffixes = {};

  const records = lines.map(l => parseLine(l)).filter(l => l);
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    if (!currentEvent) {
      currentEvent = record;
    }
    else if (record._id === currentEvent._id) { // Merge
      suffixes[record.type] = suffixes[record.type] !== undefined ? suffixes[record.type] + 1 : 0;
      currentEvent = mergeSubRecord(currentEvent, record, suffixes[record.type]);
    }
    if (record._id !== currentEvent._id || i === (records.length - 1)) {
      events.push(currentEvent);
      currentEvent = record;
      suffixes = {};
    }
  }
  return events;
}


/**
 * Parse auditd's stupid log line format. This should work for syslog-ed or audit.log lines (the only diff should be
 * \x1d vs space separating "enriched" lines.
 */
function parseLine(line) {
  /* eslint-disable no-control-regex */
  const _line = line;
  let record;
  try {
    const enriched = /^(.*)msg='(.*)'\x1d?(.*)$/;
    if (enriched.test(line)) {
      line = enriched.exec(line).slice(1).join(' ').replace(/^\s*|\s*$/g, '');
    }
    while (line) {
      const [p, k, v] = (/^([^=]+)=("[^"]+"|[^\s\x1d]+)[\s\x1d]*/).exec(line);
      line = line.slice(p.length);
      record = record ? record : {};
      record[k] = v.replace(/^"|"$/g, '');
    }
    if(record) {
      record._id = (/audit\([^:]+:(\d+)\).*/).exec(record.msg)[1];
    }
  } catch (e) {
    console.warn(`Failed to parse log line: ${e} [line="${_line}"]`);
  }
  return record;
}


/**
 * Attempt to merge records with the same event ID. Fields are named <type>-<field>[-suffix]. Suffix is used because
 * some events have multiple records of the same type (ex PATH, and I'm not sure what else ..).
 */
function mergeSubRecord(a, b, suffix = 0) {
  const maybeHex = v => ((/^[0-9A-F]+$/).test(v) ? Buffer.from(v, 'hex').toString() : v ? v : '');
  const subFieldFilters = {
    'CWD': ['cwd'],
    'PATH': ['name'],
    'KERN_MODULE': ['name'],
    'PROCTITLE': r => ({ proctitle: maybeHex(r.proctitle) }),
    'EXECVE': r => ({ execve: `${r.a0 || ''} ${r.a1 || ''} ${r.a2 || ''} ${r.a3 || ''}`.trim() }), // TODO: maybeHex..
    '*': ['name'],
  };
  const f = subFieldFilters[b.type] ? subFieldFilters[b.type] : subFieldFilters['*'];
  let c = {};
  if (f instanceof Function) {
    c = f(b);
  }
  else {
    c = Object.fromEntries(f
      .filter(k => Object.keys(b).includes(k))
      .map(k => [`${b.type.toLowerCase()}-${k}` + (suffix ? `-${suffix}` : ''), b[k]]),
    );
  }
  return { ...a, ...c };
}


/**
 * Add details from watchedEventSpecs to event object.
 */
function eventToSpec(e) {
  for (const spec of watchedEventSpecs) {
    if (spec.match(e)) {
      const res = { e };
      res.desc = spec.desc instanceof Function ? spec.desc(e) : spec.desc;
      res.fields = spec.fields instanceof Function ? spec.fields(e) : [...spec.fields];
      res.level = spec.level instanceof Function ? spec.level(e) : spec.level;
      return res;
    }
  }
}


// Map some these fields to something more human readable at display time.
const fieldNameMap = k => {
  const _map = {
    'cwd-cwd': 'cwd',
    'path-name': 'path',
    'path-name-1': 'path-1',
    'path-mode': 'mode',
  };
  return _map[k] ? _map[k] : k;
};

const loggers = {
  custom: (e = {}) => {
    function messageTmpl({ e, desc, fields }) {
      return Array.from(new Set(fields))
        .filter(f => Object.keys(e).includes(f))
        .reduce((a, b) => a + ` ${fieldNameMap(b)}=${e[b]}`, `${desc}:`);
    };
    console.log(`${levelNames[e.level]}: ${messageTmpl(e)}`);
  },
  logfmt: (e = {}) => {
    console.log(
      `desc="${e.desc}" level=${levelNames[e.level]} level_code=${e.level} ` +
      e.fields.map(f => e.e[f] ? `${fieldNameMap(f)}="${e.e[f]}"` : undefined).filter(i => i).join(' ')
    );
  }
}

/**
 * Example stdin reader. Set as main and: tail -F audit.log | auditd_log_alerts.js or as audisp plugin.
 * NOTE: For some reason auditd uses multiple lines per event with lines belonging to the same event
 * having the same id. If we understand the conditional rules as to what types of event may be broken
 * into many lines when we can anticipate many lines and wait for the entire event before processing.
 * But ... we're not doing that coz meh. All line belong to a given event *should* arrive in stdin at
 * the same time but it's possible they don't and if they dont you may miss fields from the event.
 * NOTE: Only events that return have a matching spec in eventToSpec are reported on at all.
 * @see eventToSpec
 */
function stdinReader() { // eslint-disable-line
  const level = levels[process.env.AUDITD_LOG_ALERTS_STDOUT_LEVEL] ?? levels['info'];
  const loggerName = process.env.AUDITD_LOG_ALERTS_STDOUT_LOGFMT ?? 'custom';
  const logger = loggers[loggerName];
  if(!loggers[loggerName]) {
    console.error(`Unknown logger ${loggerName}`);
    process.exit(1);
  }

  process.stdin.resume();
  process.stdin.setEncoding('utf8');
  let buffer = ''; // Last unfinished line.
  process.stdin.on('data', function (text) {
    const lines = (buffer + text).split('\n');
    buffer = '';
    if(lines.length && text[text.length -1] != '\n') {
      console.warn('Read partial line.');
      buffer = lines.pop();
    }
    const events = linesToEvents(lines).map(e => eventToSpec(e)).filter(e => e).filter(e => e.level <= level);
    events.map(e => logger(e));
  });
  process.stdin.on('end', () => {
    console.warn('Read eof');
    process.exit();
  });
}


module.exports = { linesToEvents, eventToSpec, stdinReader, levels, levelNames };


if (require.main === module) {
  stdinReader();
}
