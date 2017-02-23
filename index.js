'use strict'

module.exports = makeJWT

const JWT = require('jsonwebtoken')

const defaults = {
  key: 'user',
  secret: undefined,
  tokenLookup: 'header:Authorization',
  authScheme: 'Bearer',
  verifyOptions: undefined,
  passthrough: false
}

function makeJWT (options = {}) {
  options = Object.assign({}, defaults, options)

  const { key, secret, tokenLookup, authScheme, verifyOptions, passthrough } = options

  if (!secret) {
    throw new Error('Missing the secret key')
  }

  const [via, name] = tokenLookup.split(':')

  let extractor = jwtFromHeader(name, authScheme)

  switch (via) {
    case 'query':
      extractor = jwtFromQuery(name)
      break
    case 'cookie':
      extractor = jwtFromCookie(name)
      break
    // no default
  }

  return jwt

  function jwt (ctx, next) {
    const { token, error } = extractor(ctx)

    if (!passthrough && error) {
      return ctx.res.send(401, error)
    } else if (passthrough && !token) {
      return next()
    }

    return verify(token, secret, verifyOptions)
      .then(result => {
        ctx.state[key] = result
      })
      .catch(err => {
        if (!passthrough) {
          ctx.res.send(401, err)
        }
      })
      .then(next)
  }
}

function jwtFromHeader (header, authScheme) {
  return getToken

  function getToken (ctx) {
    const auth = ctx.req.get(header) || ''
    const [scheme, token = ''] = auth.split(' ')

    return {
      token,
      error: !(scheme === authScheme && 0 < token.length) && 'Missing or invalid jwt in the request header'
    }
  }
}

function jwtFromQuery (name) {
  return getToken

  function getToken (ctx) {
    const token = ctx.req.query[name]

    return {
      token,
      error: !token && 'Missing jwt in the query string'
    }
  }
}

function jwtFromCookie (name) {
  return getToken

  function getToken (ctx) {
    const token = ctx.cookies.get(name)

    return {
      token,
      error: !token && 'Missing jwt in the cookie'
    }
  }
}

function verify (token, secret, options) {
  return new Promise((resolve, reject) => {
    JWT.verify(token, secret, options, (err, decoded) => err ? reject(err) : resolve(decoded))
  })
}
