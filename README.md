# trek-jwt

JSON Web Tokens Middleware for Trek.js


## Installation

```
$ npm install trek-jwt --save
```


## Examples

```js
'use strict'

const Engine = require('trek-engine')
const jwt = require('..')

async function start () {
  const app = new Engine()
  const secret = 'Trek Engine'

  app.use(jwt({ secret }))

  app.use(({ req, res }) => {
    res.body = req.body
  })

  app.on('error', (err, ctx) => {
    console.log(err)
  })

  app.run(3000)
}

start().catch(err => console.log(err))
```


## API

```js
const defaults = {
  key: 'user',
  secret: undefined,
  skip: false,
  tokenLookup: 'header:Authorization',
  authScheme: 'Bearer',
  verifyOptions: undefined,
  passthrough: false
}
```


## Badges

[![Build Status](https://travis-ci.org/trekjs/jwt.svg?branch=master)](https://travis-ci.org/trekjs/jwt)
[![codecov](https://codecov.io/gh/trekjs/jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/trekjs/jwt)
![](https://img.shields.io/badge/license-MIT-blue.svg)

---

> [fundon.me](https://fundon.me) &nbsp;&middot;&nbsp;
> GitHub [@fundon](https://github.com/fundon) &nbsp;&middot;&nbsp;
> Twitter [@_fundon](https://twitter.com/_fundon)
