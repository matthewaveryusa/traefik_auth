'use strict'

const crypto = require('crypto')

class HKDF {
    constructor(hashAlg, salt, ikm) {
    this.hashAlg = hashAlg;
    const hash = crypto.createHash(this.hashAlg);

    this.hashLength = hash.digest().length;
    this.salt = salt || Buffer.alloc(this.hashLength).toString();
    this.ikm = ikm;

    const hmac = crypto.createHmac(this.hashAlg, this.salt);
    hmac.update(this.ikm);
    this.prk = hmac.digest();
  }

  derive(info, size) {
    var prev = new Buffer(0);
    var output;
    var buffers = [];
    var num_blocks = Math.ceil(size / this.hashLength);
    info = new Buffer(info);

    for (var i=0; i<num_blocks; i++) {
      var hmac = crypto.createHmac(this.hashAlg, this.prk);
      var input = Buffer.concat([
        prev,
        info,
        new Buffer(String.fromCharCode(i + 1))
      ]);
      hmac.update(input);
      prev = hmac.digest();
      buffers.push(prev);
    }
    output = Buffer.concat(buffers, size);
    return output;
  }
}

module.exports = HKDF;
