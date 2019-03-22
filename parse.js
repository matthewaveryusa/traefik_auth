"use strict";

function parse_hostname(host) {
  var port

  [host, port] = host.split(':')
  const split_host = host.split('.')
  const len = split_host.length
  if(len === 1) {
    return [host]
  } else if (len === 2) {
    return [host, `.${host}`]
  } else if (len > 2) {
    const domain_tld = `.${split_host[len-2]}.${split_host[len-1]}`
    return [host, domain_tld]
  }
  return []
}

module.exports = parse_hostname;
