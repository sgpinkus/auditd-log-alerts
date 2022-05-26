const fs = require('fs');
const assert = require('assert');
const { linesToEvents } = require('./auditd_log_alerts.js');

describe('Parse various auditd log lines', () => {
  it('Should parse auditd log', () => {
    const log = fs.readFileSync('./test-data/some.log', { encoding: 'utf8' }).split('\n');
    const events = linesToEvents(log);
    assert.equal(events.length, 4);
  });
  it('Should parse auditd with the same event many times', () => {
    const log = fs.readFileSync('./test-data/user-login.log', { encoding: 'utf8' }).split('\n');
    const events = linesToEvents(log);
    assert.equal(events.length, 17);
    assert.equal(events[0]['exe'], '/usr/sbin/sshd');
  });
  it('Should parse single auditd log multi line event', () => {
    const log = fs.readFileSync('./test-data/cat-shadow-fail.log', { encoding: 'utf8' }).split('\n');
    const events = linesToEvents(log);
    assert.equal(events.length, 1);
    assert.equal(events[0]['path-name'], '/etc/shadow');
  });
  it('Should parse single auditd log single line event', () => {
    const log = fs.readFileSync('./test-data/user-login.log', { encoding: 'utf8' }).split('\n')[0];
    const events = linesToEvents([log]);
    assert.equal(events.length, 1);
    assert.equal(events[0]['exe'], '/usr/sbin/sshd');
  });
  it('Should parse weird enriched data format', () => {
    const log = fs.readFileSync('./test-data/sockaddr.log', { encoding: 'utf8' }).split('\n');
    const events = linesToEvents(log);
    assert.equal(events.length, 1);
    assert.equal(events[0]['type'], 'NETFILTER_CFG');
  });
});
