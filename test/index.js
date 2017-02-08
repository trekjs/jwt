import test from 'ava'
import request from 'request-promise'
import Engine from 'trek-engine'
import JWT from 'jsonwebtoken'
import jwt from '..'

const listen = app => {
  return new Promise((resolve, reject) => {
    app.run(function (err) {
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

test('should get user from header', async t => {
  const secret = 'trek engine'
  const app = new Engine()
  const options = { secret }

  app.use(jwt(options))

  app.use(async ctx => {
    ctx.res.send(200, ctx.store.get('user'))
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
    ctx.res.send(200, ctx.store.get('user'))
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
    ctx.res.send(200, ctx.store.get('user'))
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

