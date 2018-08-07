#!/usr/bin/env node

const fs = require('fs')
const rc = require('rc')
const dgram = require('dgram')
const packet = require('native-dns-packet')
const wildcard = require('wildcard2')
const sha256 = require('js-sha256').sha256;
const nem = require("nem-sdk").default;

const util = require('./util.js')
const nodes = require('./nodes.js').nodes;

const defaults = {
  port: 53,
  host: '127.0.0.1',
  logging: 'dnsproxy:query,dnsproxy:info',
  nameservers: [
    '1.1.1.1',
    '1.0.0.1'
  ],
  servers: {},
  domains: {},
  fallback_timeout: 350,
}

let config = rc('dnsproxy', defaults)

process.env.DEBUG_FD = process.env.DEBUG_FD || 1
process.env.DEBUG = process.env.DEBUG || config.logging
let d = process.env.DEBUG.split(',')
d.push('dnsproxy:error')
process.env.DEBUG = d.join(',')
const loginfo = require('debug')('dnsproxy:info')
const logdebug = require('debug')('dnsproxy:debug')
const logquery = require('debug')('dnsproxy:query')
const logerror = require('debug')('dnsproxy:error')
logdebug('options: %j', config)
process.on(`unhandledRejection`, console.dir);



const server = dgram.createSocket('udp4')


function getPointerAccount(namespace) {

  passphrase = sha256(namespace);
  passphrase = nem.utils.convert.hex2ua(passphrase);
  passphrase = nem.utils.convert.ua2words(passphrase, 32);

  let privateKey = nem.crypto.helpers.derivePassSha(passphrase, 1).priv;


  const keyPair = nem.crypto.keyPair.create(privateKey);

  const publicKey = keyPair.publicKey.toString();

  const address = nem.model.address.toAddress(publicKey, nem.model.network.data.mainnet.id);

  return address;

}
function isIpAdd(str) {
  var arg = /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;
  if (str.match(arg) == null) {
    return false;
  }
  else {
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
  var hex = hex.toString();//force conversion
  var str = '';
  for (var i = 0; i < hex.length; i += 2)
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return str;
}

async function getNamespaceOwner(namespace) {
  const endpoint = getEndpoint(nodes);
  let res = await nem.com.requests.namespace.info(endpoint, namespace);
  return res.owner;

}
async function getPointerTransactions(address) {
  const endpoint = getEndpoint(nodes);
  let res = await nem.com.requests.account.transactions.incoming(endpoint, address);
  return res;
}
function getEndpoint(nodes) {
  const node = nodes[Math.floor(Math.random() * nodes.length)];
  const endpoint = nem.model.objects.create("endpoint")(`${node.protocol}://${node.domain}`, `${node.port}`);
  return endpoint;
}

async function serchNemDNS(message, rinfo) {
  
  let returner = false
  let nameserver = config.nameservers[0]

  const query = packet.parse(message)
  const domain = query.question[0].name
  const type = query.question[0].type

  logdebug('query: %j', query)

  var splitDomain = domain.split('.');
  var tld = splitDomain[splitDomain.length - 1];

  const pointerAcc = getPointerAccount(splitDomain[splitDomain.length - 2])
  const ownerAcc = await getNamespaceOwner(splitDomain[splitDomain.length - 2])

  const incomingTransactions = await getPointerTransactions(pointerAcc);
  if (incomingTransactions.data.length <= 0) {
    return false;
  }
  for (var i in incomingTransactions.data) {
    let senderAcc = nem.model.address.toAddress(incomingTransactions.data[i].transaction.signer, nem.model.network.data.mainnet.id);
    if (senderAcc == ownerAcc) {
      break;
    }
  }
  let payload = convertFromHex(incomingTransactions.data[1].transaction.message.payload);
  if (!isJSON(payload)) {
    return false;
  }
  payload = JSON.parse(payload);
  if (isIpAdd(payload.ip1)) {
    let answer = payload.ip1;
    logquery('type: server, domain: %s, answer: %s, source: %s:%s, size: %d', domain, payload.ip1, rinfo.address, rinfo.port, rinfo.size)
    let res = util.createAnswer(query, answer)
    server.send(res, 0, res.length, rinfo.port, rinfo.address)
    return true;
  }
  else {
    return false;
  }
}

server.on('listening', function () {
  loginfo('we are up and listening at %s on %s', config.host, config.port)
})

server.on('error', function (err) {
  logerror('udp socket error')
  logerror(err)
})

server.on('message', async function (message, rinfo) {
  let returner = false
  let nameserver = config.nameservers[0]

  const query = packet.parse(message)
  const domain = query.question[0].name
  const type = query.question[0].type

  logdebug('query: %j', query)

  var splitDomain = domain.split('.');
  var tld = splitDomain[splitDomain.length - 1];
  if (tld == 'nem') {
    returner = await serchNemDNS(message, rinfo)

  }




  Object.keys(config.domains).forEach(function (s) {
    let sLen = s.length
    let dLen = domain.length

    if ((domain.indexOf(s) >= 0 && domain.indexOf(s) === (dLen - sLen)) || wildcard(domain, s)) {
      let answer = config.domains[s]
      if (typeof config.domains[config.domains[s]] !== 'undefined') {
        answer = config.domains[config.domains[s]]
      }

      logquery('type: server, domain: %s, answer: %s, source: %s:%s, size: %d', domain, config.domains[s], rinfo.address, rinfo.port, rinfo.size)

      let res = util.createAnswer(query, answer)
      server.send(res, 0, res.length, rinfo.port, rinfo.address)

      returner = true
    }
  })

  if (returner) {
    return
  }

  Object.keys(config.servers).forEach(function (s) {
    if (domain.indexOf(s) !== -1) {
      nameserver = config.servers[s]
    }
  })
  let nameParts = nameserver.split(':')
  nameserver = nameParts[0]
  let port = nameParts[1] || 53
  let fallback
  (function queryns(message, nameserver) {
    const sock = dgram.createSocket('udp4')
    sock.send(message, 0, message.length, port, nameserver, function () {
      fallback = setTimeout(function () {
        queryns(message, config.nameservers[0])
      }, config.fallback_timeout)
    })
    sock.on('error', function (err) {
      logerror('Socket Error: %s', err)
      process.exit(5)
    })
    sock.on('message', function (response) {
      clearTimeout(fallback)
      logquery('type: primary, nameserver: %s, query: %s, type: %s, answer: %s, source: %s:%s, size: %d', nameserver, domain, util.records[type] || 'unknown', util.listAnswer(response), rinfo.address, rinfo.port, rinfo.size)
      server.send(response, 0, response.length, rinfo.port, rinfo.address)
      sock.close()
    })
  }(message, nameserver))
})

server.bind(config.port, config.host)
