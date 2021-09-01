// Example cloudwatch logs lambda filter. Need to adjust to do something useful like send alert to SNS or Slack.
const zlib = require('zlib');
const { linesToEvents, eventToSpec, levels, levelNames } = require('./auditd_log_alerts');


async function cloudWatchReader(payload, _context) {
  function unZipPayload(payload) {
    return new Promise(function (resolve, reject) {
      zlib.gunzip(payload, function (error, result) {
        if (error) reject(error);
        else resolve(JSON.parse(result.toString('ascii')));
      });
    });
  }
  try {
    const event = await unZipPayload(Buffer.from(payload.awslogs.data, 'base64'));
    if (!RegExp('/var/log/audit/audit.log').test(event.logStream)) {
      return;
    }
    const lines = event.logEvents.map(l => l.message);
    const events = linesToEvents(lines).map(e => eventToSpec(e)).filter(e => e);
    const messages = events.filter(e => e.level < levels.debug);
    console.debug(`Found ${lines.length} lines, ${events.length} events, ${messages.length} messages`);
    messages.map(e => {
      const face = ['🤬', '🤬', '🤬', '😧', '🧐', '🧐', '🤖', '🤖'][e.level] || '🤬';
      const color = ['#ff0000', '#ff0000', '#ff0000', '#ffce00', '#cece00', '#afaf6f', '#2b8fc9', '#2b8fc9'][e.level] || '#ffce00';
      // TODO: some more useful ->
      console.log(`<p><span color="${color}">${levelNames[e.level]} ${face}:</span>${e.msg}</p>`);
    });
  }
  catch (error) {
    console.error(error);
  }
}


exports.handler = cloudWatchReader;
