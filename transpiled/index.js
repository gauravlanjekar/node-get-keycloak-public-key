'use strict';

var http = require('http');
var https = require('https');

var BEGIN_KEY = '-----BEGIN RSA PUBLIC KEY-----\n';
var END_KEY = '\n-----END RSA PUBLIC KEY-----\n';

module.exports = function KeycloakPublicKeyFetcher(url, realm) {
  var certsUrl = realm ? url + '/auth/realms/' + realm + '/protocol/openid-connect/certs' : url;
  return {
    fetch: function fetch(kid) {
      return _fetch(certsUrl, kid);
    }
  };
};

function _fetch(url, kid) {
  return getJson(url).then(function (response) {
    var key = getKey(response, kid);
    if (!key) {
      throw new Error('Can\'t find key for kid "' + kid + '" in response.');
    }
    verify(key);
    return new Promise(function (resolve, reject) {
      resolve(getPublicKey(key.n, key.e));
    });
  });
}

function getJson(url) {
  return new Promise(function (resolve, reject) {
    var agent = url.startsWith('https') ? https : http;
    agent.get(url, function (res) {
      if (!valid(res)) {
        res.resume();
        reject(new Error('Status: ' + res.statusCode + ', Content-type: ' + res.headers['content-type']));
      }
      parse(res).then(function (result) {
        return resolve(result);
      }).catch(function (error) {
        return reject(error);
      });
    }).on('error', function (e) {
      reject(e);
    });
  });
}

function valid(response) {
  return response.statusCode === 200 && response.headers['content-type'] === 'application/json';
}

function parse(response) {
  return new Promise(function (resolve, reject) {
    var rawData = '';
    response.setEncoding('utf8');
    response.on('data', function (chunk) {
      rawData += chunk;
    });
    response.on('end', function () {
      try {
        var parsedData = JSON.parse(rawData);
        resolve(parsedData);
      } catch (e) {
        reject(e);
      }
    });
  });
}

function getKey(response, kid) {
  return Object.hasOwnProperty.call(response, 'keys') ? response.keys.find(function (k) {
    return k.kid === kid;
  }) : undefined;
}

function verify(key) {
  if (!(key.n && key.e)) {
    throw new Error('Can\'t find modulus or exponent in key.');
  }
  if (key.kty !== 'RSA') {
    throw new Error('Key type (kty) must be RSA.');
  }
  if (key.alg !== 'RS256') {
    throw new Error('Algorithm (alg) must be RS256.');
  }
}

// Based on tracker1's node-rsa-pem-from-mod-exp module.
// See https://github.com/tracker1/node-rsa-pem-from-mod-exp
function getPublicKey(modulus, exponent) {
  var mod = convertToHex(modulus);
  var exp = convertToHex(exponent);
  var encModLen = encodeLenght(mod.length / 2);
  var encExpLen = encodeLenght(exp.length / 2);
  var part = [mod, exp, encModLen, encExpLen].map(function (n) {
    return n.length / 2;
  }).reduce(function (a, b) {
    return a + b;
  });
  var bufferSource = '30' + encodeLenght(part + 2) + '02' + encModLen + mod + '02' + encExpLen + exp;
  var pubkey = Buffer.from(bufferSource, 'hex').toString('base64');
  return BEGIN_KEY + pubkey.match(/.{1,64}/g).join('\n') + END_KEY;
}

function convertToHex(str) {
  var hex = Buffer.from(str, 'base64').toString('hex');
  return hex[0] < '0' || hex[0] > '7' ? '00' + hex : hex;
}

function encodeLenght(n) {
  return n <= 127 ? toHex(n) : toLongHex(n);
}

function toLongHex(number) {
  var str = toHex(number);
  var lengthByteLength = 128 + str.length / 2;
  return toHex(lengthByteLength) + str;
}

function toHex(number) {
  var str = number.toString(16);
  return str.length % 2 ? '0' + str : str;
}