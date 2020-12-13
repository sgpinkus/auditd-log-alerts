#!/usr/bin/env python3
'''
'''
import os
import sys
import re
import fcntl
import select # https://docs.python.org/3/library/select.html
import signal
import audit
import logging
from logging.handlers import SysLogHandler
name = 'my-audit'
import time


def main():
  try:
    os.chdir('/')
    logger.info('Starting ..')
    reader = LineReader()
    for event in readEvents(reader):
      logger.info(event)
      dispatch(event)
    logger.info('Read EOF. Exiting..')
  except Exception as e:
    logger.error(str(e))
    sys.exit(1)


class LineReader():
  def __init__(self):
    f = os.fdopen(sys.stdin.fileno(), 'r')
    fcntl.fcntl(f.fileno(), fcntl.F_SETFL, fcntl.fcntl(f, fcntl.F_GETFL) | os.O_NONBLOCK)
    self.f = f

  def read(self):
    while True:
      [r, w, e] = select.select([self.f], [], [])
      if r:
        lines = self.f.readlines()
        if not lines:
          return None
        return lines


def readEvents(reader):
  ''' For some reason auditd decided they needed to split logical event records into >1 lines. Lines belonging to the
  same event are identified by an id. A lot of details are not clearly stated about what a reader can expect, but I'm
  assuming events with same ID are contiguous and available "all at once".
  '''
  records = []
  currentEvent = None
  suffixes =  {}
  while True:
    lines = reader.read()
    if not lines:
      return
    records.extend([parseLine(record) for record in reversed(lines)]) # records are \n terminated.
    while records:
      record = records.pop()
      if not currentEvent:
        currentEvent = record
      elif record['_id'] == currentEvent['_id']:
        suffixes[record['type']] = suffixes[record['type']] + 1 if record['type'] in suffixes else 0
        currentEvent = merge(currentEvent, record, suffixes[record['type']])
      if record['_id'] != currentEvent['_id'] or not records:
        yield currentEvent # enrich(currentEvent)
        currentEvent = record
        suffixes = {}


def merge(a = {}, b = {}, suffix = 0):
  ''' Try and merge multiline records into logical record dict. To avoid collisions we don't just pick everything and in
  turn need to know something about what fields a given type has.
  '''
  filters = {
    'CWD': ['cwd'],
    'PATH': ['name'],
    'KERN_MODULE': ['name'],
    'PROCTITLE': ['proctitle'],
    '*': ['name'],
  }
  t = b['type']
  f = filters[t] if t in filters.keys() else filters['*']
  for k in f:
    if k in b.keys():
      a[('%s-%s' % (t.lower(), k)) + ('-%s' % (suffix,) if suffix else '')] = b[k]
  return a


def parseLine(line):
  ''' There is two types of log records one with the weird non standard msg='<bunch-of-fields>' and one which is just std
  auditd record as described in the docs. I'm not sure why they've done this. One is for user space services other is for
  kernel module? I'm just flattening out msg='' fields here. Technically there is alos supposed to be a non printable \x1D
  separator between main message and enriched text. But not using that as it's only reliably present in the direct
  output from auditd.
  '''
  m = re.match('''^(.*)msg=\'(.*)\'(.*)$''', line)
  if m:
    a, b, c = m.groups()
    r = (a + b + ' ' + c).strip()
  else:
    r = line
  f = {}
  while r:
    m = re.match('^([^=]+)=("[^"]+"|[^\s]+)\s*', r)
    [k, v] = m.groups()
    r = r[m.end():].strip()
    f[k] = v.strip('"')
  f['_id'] = re.match('audit\([^:]+:(\d+)\).*', f['msg']).groups()[0]
  return f


def dispatch(e = {}):
  ''' Dispatch known events to a printer. '''
  handlers = [
    {
      'm': lambda e: e['type'] == 'USER_LOGIN',
      'h': loginAlert
    },
    {
      'm': lambda e: e['type'] == 'USER_START',
      'h': loginAlert
    },
    {
      'm': lambda e: e['type'] == 'ANOM_LOGIN_FAILURES',
      'h': printIt,
    },
    {
      'm': lambda e: e['type'] == 'ANOM_LOGIN_SESSIONS',
      'h': printIt,
    },
    {
      'm': lambda e: e['type'] == 'ANOM_LOGIN_LOCATION',
      'h': printIt,
    },
    {
      'm': lambda e: e['type'] == 'ANOM_LOGIN_TIME',
      'h': printIt,
    },
    {
      'm': lambda e: e['type'] == 'AUDIT_AVC',
      'h': printIt,
    },
    {
      'm': lambda e: e['type'] == 'USER_AVC',
      'h': printIt
    },
    {
      'm': lambda e: e['type'] == 'ANOM_ABEND',
      'h': abEnd
    },
    {
      'm': lambda e: e['type'] == 'ANOM_PROMISCUOUS',
      'h': printIt
    },
    {
      'm': lambda e: e['type'] == 'MAC_STATUS',
      'h': printIt
    },
    {
      'm': lambda e: e['type'] == 'TTY',
      'h': printIt
    },
    {
      'm': lambda e: e['type'] == 'GRP_AUTH' and 'res' in e and e['res'] == 'failure',
      'h': printIt
    },
    {
      'm': lambda e: e['type'] == 'SYSCALL',
      'h': dispatchStigWatches
    },

  ]
  for handler in handlers:
    if handler['m'](e):
      handler['h'](e)


def dispatchStigWatches(e):
  ''' access code data delete export MAC module perm_mod power privileged register system time tracing. '''
  messages = {
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
  }
  try:
    key = e['key'] if 'key' in e else ''
    printIt(e, messages[key])
  except:
    printIt(e)

def printIt(e, msg = 'Watch'):
  ''' '''
  e = e.copy()
  logger.info('{msg}: {e}'.format(msg=msg, e=e))


def initLogger():
  ''' https://docs.python.org/3/library/logging.handlers.html#sysloghandler '''
  handler = SysLogHandler(address="/dev/log")
  formatter = logging.Formatter('{name}[{process}]: {levelname}: {message}', style='{')
  handler.setFormatter(formatter);
  logging.basicConfig(handlers=[handler, logging.StreamHandler()])
  logging.getLogger().setLevel(logging.DEBUG)
  return logging.getLogger(name)


def initSignals():
  signal.signal(signal.SIGTERM, term)
  signal.signal(signal.SIGCHLD, term)
  signal.signal(signal.SIGHUP, signal.SIG_IGN)


def term():
  logger.info('Exiting');
  sys.exit(0);


logger = initLogger()
main()
