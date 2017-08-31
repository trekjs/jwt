/*!
 * sessions-provider-memory
 * Copyright(c) 2017 Fangdun Cai <cfddream@gmail.com> (https://fundon.me)
 * MIT Licensed
 */

'use strict'

module.exports = jwtWithConfig

const JWT = require('jsonwebtoken')

const MISSING = {
  code: 400,
  message: 'Missing or malformed jwt'
}

const INVALID = {
  code: 401,
  message: 'Invalid or expired jwt'
}

const defaults = {
  key: 'user',
  secret: undefined,
  tokenLookup: 'header:Authorization',
  authScheme: 'Bearer',
  verifyOptions: undefined,
  passthrough: false
}

function jwtWithConfig(options = {}) {
  options = Object.assign({}, defaults, options)

  const {
    key,
    secret,
    tokenLookup,
    authScheme,
    verifyOptions,
    passthrough,
    errors = {}
  } = options

  if (!secret) {
    throw new Error('Missing the secret key')
  }

  const missing = Object.assign(MISSING, errors.missing)
  const invalid = Object.assign(INVALID, errors.invalid)

  const [via, name] = tokenLookup.split(':')

  let extractor

  switch (via) {
    case 'query':
      extractor = jwtFromQuery
      break
    case 'cookie':
      extractor = jwtFromCookie
      break
    default:
      extractor = jwtFromHeader
  }

  return jwt

  function jwt(ctx, next) {
    const { hasError, token } = extractor(ctx, name, authScheme)

    if (!passthrough && hasError) {
      return ctx.res.send(missing.code, missing.message)
    } else if (passthrough && !token) {
      return next()
    }

    return verify(token, secret, verifyOptions)
      .then(result => {
        ctx.state[key] = result
      })
      .catch(() => {
        if (!passthrough) {
          ctx.res.send(invalid.code, invalid.message)
        }
      })
      .then(next)
  }
}

function jwtFromHeader(ctx, header, authScheme) {
  const auth = ctx.req.get(header) || ''
  const [scheme, token = ''] = auth.split(' ')

  return {
    token,
    hasError: !(scheme === authScheme && token.length > 0)
  }
}

function jwtFromQuery(ctx, name) {
  const token = ctx.req.query[name]

  return {
    token,
    hasError: !token
  }
}

function jwtFromCookie(ctx, name) {
  const token = ctx.cookies.get(name)

  return {
    token,
    hasError: !token
  }
}

function verify(token, secret, options) {
  return new Promise((resolve, reject) => {
    JWT.verify(
      token,
      secret,
      options,
      (err, decoded) => (err ? reject(err) : resolve(decoded))
    )
  })
}
