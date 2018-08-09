#!/usr/bin/env node

const dgram = require('dgram')
const packet = require('native-dns-packet')
const sha256 = require('js-sha256').sha256;
const nem = require("nem-sdk").default;
const util = require('./util.js')
const nodes = require('./nodes.js').nodes;
const config = {
  port: 53,
  host: '127.0.0.1',
  logging: 'dnsproxy:resNEMDNS,dnsproxy:resDNS,dnsproxy:info,dnsproxy:request',
  nameservers: [
    '1.1.1.1',
    '1.0.0.1'
  ],
  fallback_timeout: 350,
}
let nameserver;

//Logging parameter set
process.env.DEBUG_FD = process.env.DEBUG_FD || 1
process.env.DEBUG = process.env.DEBUG || config.logging
let d = process.env.DEBUG.split(',')
d.push('dnsproxy:error')
process.env.DEBUG = d.join(',')
const loginfo = require('debug')('dnsproxy:info')
const logResNEMDNS = require('debug')('dnsproxy:resNEMDNS')
const logResDNS = require('debug')('dnsproxy:resDNS')
const logrequest = require('debug')('dnsproxy:request')
const logerror = require('debug')('dnsproxy:error')

process.on(`unhandledRejection`, console.dir);
const server = dgram.createSocket('udp4')

function isIpAdd(str) {
  var arg =
    /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;
  if (str.match(arg) == null) {
    return false;
  } else {
    return true;
  }
}

function isJSON(arg) {
  arg = (typeof arg === "function") ? arg() : arg;
  if (typeof arg !== "string") {
    return false;
  }
  try {
    arg = (!JSON) ? eval("(" + arg + ")") : JSON.parse(arg);
    return true;
  } catch (e) {

    return false;
  }
};

function convertFromHex(hex) {
  var hex = hex.toString(); //force conversion
  var str = '';
  for (var i = 0; i < hex.length; i += 2)
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return str;
}

function getPointerAccount(namespace) {
  passphrase = sha256(namespace);
  passphrase = nem.utils.convert.hex2ua(passphrase);
  passphrase = nem.utils.convert.ua2words(passphrase, 32);
  let privateKey = nem.crypto.helpers.derivePassSha(passphrase, 1).priv;
  const keyPair = nem.crypto.keyPair.create(privateKey);
  const publicKey = keyPair.publicKey.toString();
  const address = nem.model.address.toAddress(publicKey, nem.model.network.data.mainnet
    .id);
  return address;
}
async function getNamespaceOwner(namespace) {
  const endpoint = getEndpoint(nodes);
  let res = await nem.com.requests.namespace.info(endpoint, namespace);
  return res.owner;
}

async function getPointerTransactions(namespace) {
  const endpoint = getEndpoint(nodes);
  const address = getPointerAccount(namespace);
  let res = await nem.com.requests.account.transactions.incoming(endpoint, address);
  return res;
}

function getEndpoint(nodes) {
  const node = nodes[Math.floor(Math.random() * nodes.length)];
  const endpoint = nem.model.objects.create("endpoint")(
    `${node.protocol}://${node.domain}`, `${node.port}`);
  return endpoint;
}
function getAccountFromPublickey(publicKey) {
  const res = nem.model.address.toAddress(publicKey, nem.model.network.data.mainnet.id)
  return res;
}
async function serchNemDNS(message, rinfo) {
  const query = packet.parse(message)
  const domain = query.question[0].name
  var splitDomain = domain.split('.');
  var tld = splitDomain[splitDomain.length - 1];
  if (tld != 'nem') {
    return false;
  }
  var splitDomain = domain.split('.');
  const namespace = splitDomain[splitDomain.length - 2];
  const ownerAcc = await getNamespaceOwner(namespace)
  const incomingTransactions = await getPointerTransactions(namespace);
  if (incomingTransactions.data.length <= 0) {
    return false;
  }
  for (var i in incomingTransactions.data) {
    let senderAcc = getAccountFromPublickey(incomingTransactions.data[i].transaction.signer);
    if (senderAcc == ownerAcc) {
      break;
    }
  }
  let payload = convertFromHex(incomingTransactions.data[i].transaction.message.payload);
  if (!isJSON(payload)) {
    return false;
  }
  payload = JSON.parse(payload);
  if (isIpAdd(payload.ip1)) {
    let answerIP = payload.ip1;
    logResNEMDNS('type: server, domain: %s, answer: %s, source: %s:%s, size: %d',
      domain, payload.ip1, rinfo.address, rinfo.port, rinfo.size)
    let res = util.createAAnswer(query, answerIP)
    server.send(res, 0, res.length, rinfo.port, rinfo.address)
    return true;
  } else {
    nameserver = config.nameservers[Math.floor(Math.random() * config.nameservers.length)];
    const port = 53;
    let fallback;
    const sock = dgram.createSocket('udp4')
    query.question[0].name = payload.ip1;
    packet.write(message,query);
    sock.send(message, 0, message.length, port, nameserver, function () {
      fallback = setTimeout(function () {
        serchDNS(message, rinfo)
      }, config.fallback_timeout)
    })
    sock.on('error', function (err) {
      logerror('Socket Error: %s', err)
      process.exit(5)
    })
    sock.on('message', function (response) {
      clearTimeout(fallback)
      logResDNS(
        'type: primary, nameserver: %s, query: %s, type: %s, answer: %s, source: %s:%s, size: %d',
        nameserver, domain, util.records[query.question[0].type] || 'unknown', util.listAnswer(
          response), rinfo.address, rinfo.port, rinfo.size)
      server.send(response, 0, response.length, rinfo.port, rinfo.address)
      sock.close()
    })
  }
}

function serchDNS(message, rinfo) {
  const query = packet.parse(message)
  const domain = query.question[0].name
  nameserver = config.nameservers[Math.floor(Math.random() * config.nameservers.length)];
  const port = 53;
  let fallback;
  const sock = dgram.createSocket('udp4')
  sock.send(message, 0, message.length, port, nameserver, function () {
    fallback = setTimeout(function () {
      serchDNS(message, rinfo)
    }, config.fallback_timeout)
  })
  sock.on('error', function (err) {
    logerror('Socket Error: %s', err)
    process.exit(5)
  })
  sock.on('message', function (response) {
    clearTimeout(fallback)
    logResDNS(
      'type: primary, nameserver: %s, query: %s, type: %s, answer: %s, source: %s:%s, size: %d',
      nameserver, domain, util.records[query.question[0].type] || 'unknown', util.listAnswer(
        response), rinfo.address, rinfo.port, rinfo.size)
    server.send(response, 0, response.length, rinfo.port, rinfo.address)
    sock.close()
  })
}
server.on('listening', function () {
  loginfo('we are up and listening at %s on %s', config.host, config.port);
})

server.on('error', function (err) {
  logerror('udp socket error')
  logerror(err)
})
server.on('message', function (message, rinfo) {
  serchNemDNS(message, rinfo).then(
    (returner) => {
      if (!returner) {
        serchDNS(message, rinfo);

      }
    })
})
server.bind(config.port, config.host)
