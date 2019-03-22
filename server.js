'use strict'

const crypto = require('crypto')
const bcrypt = require('bcrypt')

const express = require('express')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const qs = require('querystring')
const url = require('url')
const HKDF = require('./hkdf.js')
const parse_hostname = require('./parse.js')
const sqlite3 = require('better-sqlite3')

const db = new sqlite3('/app/data/auth.sqlite3')
db.exec(`CREATE TABLE IF NOT EXISTS roles (role TEXT NOT NULL);
CREATE INDEX if not exists idx1 ON roles(role);
CREATE TABLE IF NOT EXISTS users (user TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX  if not exists idx2 ON users(user);
CREATE TABLE IF NOT EXISTS users_roles (user TEXT NOT NULL, role TEXT NOT NULL);
CREATE INDEX  if not exists idx3 ON users_roles(user,role);
CREATE TABLE IF NOT EXISTS resources (resource TEXT NOT NULL);
CREATE INDEX  if not exists idx4 ON resources(resource);
CREATE TABLE IF NOT EXISTS resources_roles (resource TEXT NOT NULL, role TEXT);
CREATE INDEX  if not exists idx5 ON resources_roles(resource, role);`)

const get_roles = db.prepare('SELECT role FROM roles')
const insert_role = db.prepare('INSERT INTO roles (role) VALUES (@role)')
const delete_role = db.prepare('DELETE FROM roles WHERE role = @role')

const get_users = db.prepare('SELECT user FROM users')
const get_user = db.prepare('SELECT user,hash FROM users WHERE user = @user')
const insert_user = db.prepare('INSERT INTO users (user) VALUES (@user)')
const delete_user = db.prepare('DELETE FROM users WHERE user = @user')
const update_user = db.prepare('UPDATE users SET hash = @hash WHERE user = @user')

const get_user_roles = db.prepare('SELECT user,role FROM users_roles')
const insert_user_role = db.prepare('INSERT INTO users_roles (user, role) VALUES (@user, @role)')
const delete_user_role = db.prepare('DELETE FROM users_roles WHERE user = @user and role = @role')

const get_resources = db.prepare('SELECT resource FROM resources')
const insert_resource = db.prepare('INSERT INTO resources (resource) VALUES (@resource)')
const delete_resource = db.prepare('DELETE FROM resources WHERE resource = @resource')

const get_resources_roles = db.prepare('SELECT resource,role FROM resources_roles')
const insert_resource_role = db.prepare('INSERT INTO resources_roles (resource, role) VALUES (@resource, @role)')
const delete_resource_role = db.prepare('DELETE FROM resources_roles WHERE resource = @resource and role = @role')
const delete_resource_all_role = db.prepare('DELETE FROM resources_roles WHERE resource = @resource and role IS NULL')

const check_resource = db.prepare('SELECT role FROM resources_roles WHERE resource = @resource AND (role IN (SELECT role FROM users_roles WHERE user = @user) OR role IS NULL) GROUP BY resource;')

function check_authorization(db, host, user) {
  const hosts = parse_hostname(host)
  console.log('check hosts:',hosts)
  for(let i = 0; i < hosts.length; i++) {
    const host = hosts[i]
    const results = check_resource.all({resource: host, user: user || ''});
    if(results.length !== 0) {
      return results
    }
  }
  return [];
}

const domain = 'check.averymatt.com'
const cookie_domain = '.averymatt.com'
const base_domain = 'averymatt.com'
const csrf_secret = crypto.randomBytes(32)

const hkdf = {
  hkdf: new HKDF('sha256', '', crypto.randomBytes(32)),
  it: 0
}

const auth_secret = crypto.randomBytes(32)

const app = express()

app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser());

app.get('/auth', authenticate)
app.get('/login', login_input)
app.post('/login', login)

//app.get('/users', get_users)
//app.get('/user', get_user)
//app.post('/user', add_user)
//app.put('/user', update_user)
//app.delete('/user', delete_user)
//
//app.get('/roles', get_roles)
//app.post('/role', add_role)
//app.delete('/role', delete_role)
//
//app.get('/user_roles', get_user_roles)
//app.post('/user_role', add_user_role)
//app.delete('/user_role', delete_user_role)
//
//app.get('/resources', get_user_roles)
//app.post('/resource', add_resource)
//app.delete('/resource', delete_resource)
//
//app.get('/role_resources', get_role_resources)
//app.post('/role_resource', add_role_resource)
//app.delete('/role_resource', delete_role_resource)

app.listen(3000, function (err) {
  if (err) {
    throw err
  }
  console.log('Server started on port 80')
})

function authenticate(req, res) {
  const uri = req.get('X-Forwarded-URI')
  const host = req.get('X-Forwarded-Host')
  //bootstrapping problem on the checker domain
  if(host === domain) {
    res.status(200).send('OK');
    return
  }
  console.log('authenticate',uri, host);
  try {
    let user = ''
    if('authn' in req.cookies) {
      try {
      const ret = jwt.verify(req.cookies.authn, auth_secret);
              user = ret.user
      } catch (err) {
      }
    }
    const auths = check_authorization(db, host, user)
    console.log(auths)
    if(auths.length === 0) {
      throw Error('not authorized')
    }
    res.writeHead(200,{'X-Auth-User':user})
    res.end('OK');
  } catch (err) {
    console.log(err)
    hkdf.it++;
    const csrf = jwt.sign({ nonce: hkdf.hkdf.derive(hkdf.it.toString(), 32).toString('base64') }, csrf_secret, {expiresIn: '24h'});
    res.cookie('csrf', csrf, {secure: true, domain: cookie_domain});
    res.status(401).send(login_form_str(csrf, uri, host))
  }
}

function login_input(req, res) {
        hkdf.it++;
	const csrf = jwt.sign({ nonce: hkdf.hkdf.derive(hkdf.it.toString(), 32).toString('base64') }, csrf_secret, {expiresIn: '24h'});
        res.cookie('csrf', csrf, {secure: true, domain: cookie_domain});
	const query = url.parse(req.url, true).query;
	const host = query.host || base_domain
	const uri = query.uri || "/"
        console.log('login_input',uri, host);
	

	res.status(401).send(login_form_str(csrf, uri, host)) }

function login_form_str(csrf, uri, host) {
 return `<form id="loginform" action="https://${domain}/login" method="post">
    <div>
        <label for="user">username: </label><br>
        <input type="text" id="user" name="user"></input><br>
        <label for="password">password: </label><br>
        <input type="password" id="password" name="password"></input><br>
        <input type="hidden" name="csrf" value="${csrf}" />
        <input type="hidden" name="uri" value="${uri}" />
        <input type="hidden" name="host" value="${host}" />
    </div>
<input type="submit" value="Submit"></input>
</form>`
}

function login(req, res) {
  console.log('login_post',req.cookies, req.body)
  const uri = req.body.uri
  const host = req.body.host
  if(req.cookies.csrf !== req.body.csrf) {
    console.log('csrf doesn\'t match')
    const query = qs.stringify({'uri': uri, 'host': host})
    res.status(307).redirect(`https://${domain}/login?${query}`);
    return;
  }
  try {
    jwt.verify(req.body.csrf, csrf_secret);
    console.log('csrf ok')
    const row = get_user.get({user: req.body.user})
    if(!row) {
      throw Error('invalid username/password')
    }
    if(!bcrypt.compareSync(req.body.password, row.hash )) {
	      throw Error('invalid username/password')
    }
    const authn_token = jwt.sign({user: req.body.user}, auth_secret, {expiresIn: '1y'});
    res.cookie('authn', authn_token, { secure: true, domain: cookie_domain});
    
    const auths = check_authorization(db, host, req.body.user)
    console.log(auths)
    if(auths.length === 0) {
      throw Error('not authorized')
    }
    console.log('login', uri, host);
    res.redirect(`https://${host}${uri}`);
    return;
  } catch (err) {
    console.log('csrf error', err)
    const query = qs.stringify({'uri': uri, 'host': host})
    res.status(307).redirect(`https://${domain}/login?${query}`);
    return;
  }
}

