const WebSocketServer = require('websocket').server;
const http = require('http');
const { log, debug } = require('./log');

let incomming = {};
setInterval(() => {
  // Reset 'incomming' list every 5 minutes
  incomming = {};
}, 300000);

const httpServer = http.createServer((rq, rs) => {
  if (rq.url === '/ping') {
    rs.setHeader('Access-Control-Allow-Origin', '*');
    rs.end('pong');
  }
});

httpServer.listen(process.env.PORT || 3000);

exports.server = new WebSocketServer({
  httpServer,
});

exports.server.on('request', async (rq) => {
  const ip = rq.remoteAddresses.join('@');
  debug('Connect', ip);

  if (
    incomming[ip]
    && (Date.now() - incomming[ip].last) < (5000 / incomming[ip].i)
  ) {
    log('Banned IP', ip);
    rq.reject(403);
    return;
  }

  if (!incomming[ip]) incomming[ip] = { i: 0 };
  incomming[ip].l = Date.now();
  incomming[ip].l += 1;

  if (!rq.origin || !rq.origin.includes('/')) {
    log('Wrong request: no origin', rq.origin);
    rq.reject(400);
    return;
  }

  const originHost = rq.origin.split('/');

  if (!originHost || !originHost[2] || ![
    'miakapp.com',
    'coordinator.miakapp',
    'miakapp-3.web.app',
    'beta.miakapp.com',
    'dev.miakapp.com:8080',
  ].includes(originHost[2])) {
    log('Wrong origin', originHost);
    rq.reject(400);
    return;
  }

  rq.accept();
});
