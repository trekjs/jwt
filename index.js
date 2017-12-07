/*!
 * jwt
 * Copyright(c) 2017 Fangdun Cai <cfddream@gmail.com> (https://fundon.me)
 * MIT Licensed
 */

'use strict'

module.exports = jwtWithConfig

const { promisify } = require('util')
const JWT = require('jsonwebtoken')

const verify = promisify(JWT.verify)
const sign = promisify(JWT.sign)

jwtWithConfig.verify = verify
jwtWithConfig.sign = sign

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
  skip: false,
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
    skip,
    tokenLookup,
    authScheme,
    verifyOptions,
    passthrough,
    errors = {}
  } = options

  if (!secret) {
    throw new Error('Missing the secret key')
  }

  if (skip !== false && typeof skip !== 'function') {
    throw new TypeError('option skip must be function')
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
    if (skip && skip(ctx, options)) return next()

    const { hasError, token } = extractor(ctx, name, authScheme)

    if (!passthrough && hasError) {
      return ctx.res.send(missing.code, { message: missing.message })
    } else if (passthrough && !token) {
      return next()
    }

    return verify(token, secret, verifyOptions)
      .then(result => {
        ctx.state[key] = result
      })
      .catch(() => {
        if (!passthrough) {
          ctx.res.send(invalid.code, { message: invalid.message })
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
