import test from 'ava'
import request from 'request-promise'
import Engine from 'trek-engine'
import JWT from 'jsonwebtoken'
import jwt from '..'

const listen = app => {
  return new Promise((resolve, reject) => {
    app.run(function(err) {
      if (err) {
        return reject(err)
      }
      const { port } = this.address()
      resolve(`http://localhost:${port}`)
    })
  })
}

test('should get error when missing the secret key', t => {
  const app = new Engine()
  const options = {}

  const error = t.throws(() => {
    app.use(jwt(options))
  })

  t.is(error.message, 'Missing the secret key')
})

test('should throw 400 if no authorization header', async t => {
  const secret = 'trek engine'
  const app = new Engine()
  const options = { secret }

  app.use(jwt(options))

  const url = await listen(app)
  const res = await request({
    url,
    json: true,
    simple: false,
    resolveWithFullResponse: true
  })

  const { message } = res.body
  t.is(message, 'Missing or malformed jwt')
  t.is(res.statusCode, 400)
})

test('should throw if secret provider returns a secret that does not match jwt', async t => {
  const secret = 'shhhhhh'
  const token = JWT.sign({ foo: 'bar' }, secret)
  const options = { secret: 'not my secret' }

  const app = new Engine()

  app.use(jwt(options))

  app.use(({ res }) => {
    res.body = secret
  })

  const url = await listen(app)
  const res = await request({
    url,
    json: true,
    simple: false,
    resolveWithFullResponse: true,
    headers: {
      Authorization: 'Bearer ' + token
    }
  })

  const { message } = res.body
  t.true(/Invalid/.test(message))
  t.is(res.statusCode, 401)
})

test('should continue if `passthrough` is true', async t => {
  const secret = 'trek engine'
  const app = new Engine()
  const options = { secret, passthrough: true }

  app.use(jwt(options))

  app.use(({ res }) => {
    res.body = null
  })

  const url = await listen(app)
  const res = await request({
    url,
    simple: false,
    resolveWithFullResponse: true
  })

  t.is(res.body, '')
  t.is(res.statusCode, 204)
})

test('should get user from header', async t => {
  const secret = 'trek engine'
  const app = new Engine()
  const options = { secret }

  app.use(jwt(options))

  app.use(async ctx => {
    ctx.res.send(200, ctx.state.user)
  })

  const url = await listen(app)
  const res = await request({
    url,
    json: true,
    simple: false,
    resolveWithFullResponse: true,
    headers: {
      Authorization: 'Bearer ' + JWT.sign({ foor: 'bar' }, secret)
    }
  })

  t.is(res.body.foor, 'bar')
  t.is(res.statusCode, 200)
})

test('should get user from query', async t => {
  const secret = 'trek engine'
  const app = new Engine()
  const options = { secret, tokenLookup: 'query:auth' }

  app.use(jwt(options))

  app.use(async ctx => {
    ctx.res.send(200, ctx.state.user)
  })

  const url = await listen(app)
  const res = await request({
    url,
    json: true,
    simple: false,
    resolveWithFullResponse: true,
    qs: {
      auth: JWT.sign({ foor: 'bar' }, secret)
    }
  })

  t.is(res.body.foor, 'bar')
  t.is(res.statusCode, 200)
})

test('should get user from cookie', async t => {
  const secret = 'trek engine'
  const app = new Engine()
  const options = { secret, tokenLookup: 'cookie:auth' }

  app.use(jwt(options))

  app.use(async ctx => {
    ctx.res.send(200, ctx.state.user)
  })

  const url = await listen(app)
  const jar = request.jar()
  const cookie = request.cookie('auth=' + JWT.sign({ foor: 'bar' }, secret))
  jar.setCookie(cookie, url)
  const res = await request({
    url,
    jar,
    json: true,
    simple: false,
    resolveWithFullResponse: true
  })

  t.is(res.body.foor, 'bar')
  t.is(res.statusCode, 200)
})

test('should throw error when skip is true', t => {
  const secret = 'trek engine'
  const options = {
    secret,
    tokenLookup: 'cookie:auth',
    skip: true
  }

  const error = t.throws(() => {
    jwt(options)
  }, TypeError)

  t.is(error.message, 'option skip must be function')
})

test('should skip body parse', async t => {
  const secret = 'trek engine'
  const app = new Engine()
  const options = {
    secret,
    tokenLookup: 'cookie:auth',
    skip() {
      return true
    }
  }

  app.use(jwt(options))

  app.use(async ctx => {
    ctx.res.send(200, ctx.state.user)
  })

  const url = await listen(app)
  const jar = request.jar()
  const cookie = request.cookie('auth=' + JWT.sign({ foor: 'bar' }, secret))
  jar.setCookie(cookie, url)
  const res = await request({
    url,
    jar,
    json: true,
    simple: false,
    resolveWithFullResponse: true
  })

  t.is(res.body, undefined)
  t.is(res.statusCode, 200)
})
