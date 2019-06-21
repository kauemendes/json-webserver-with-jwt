const fs = require('fs')
const bodyParser = require('body-parser')
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')

const server = jsonServer.create()
const router = jsonServer.router('./database.json')
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'))

server.use(bodyParser.urlencoded({extended: true}))
server.use(bodyParser.json())
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789'

const expiresIn = '1m'
const expiresInRefreshToken = '2m'

// Create a token from a payload 
function createToken(payload){
  return jwt.sign(payload, SECRET_KEY, {expiresIn})
}

// Create a token from a payload 
function createRefreshToken(payload){
  return jwt.sign(payload, SECRET_KEY, {expiresIn: expiresInRefreshToken})
}

// Verify the token 
function verifyToken(token){
  return  jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ?  decode : err)
}

// Check if the user exists in database
function isAuthenticated({user_phone, user_identification}){
  return userdb.users.findIndex(user => user.email === user_phone && user.password === user_identification) !== -1
}


server.post('/login', (req, res) => {
  const {user_phone, user_identification} = req.body
  console.log("payload", {user_phone, user_identification})
  console.log("BODY", req.body)
  if (isAuthenticated({user_phone, user_identification}) === false) {
    const status = 401
    const message = 'Incorrect email or password'
    res.status(status).json({status, message})
    return
  }
  const refresh_token = createRefreshToken({user_phone, user_identification})
  const access_token = createToken({user_phone, user_identification})
  res.status(200).json({access_token, refresh_token})
})

server.post('/token', (req, res) => {
  const {refresh_token} = req.body
  const isValid = verifyToken(refresh_token);
  console.log("isValid", isValid);
  if ( isValid['name']  !== 'TokenExpiredError' ) {
    const access_token = createToken({user_phone: isValid.user_phone, user_identification: isValid.user_identification})
    const refresh_token = createRefreshToken({user_phone: isValid.user_phone, user_identification: isValid.user_identification})
    res.status(200).json({access_token, refresh_token})
  } else {
    const status = 403
    const message = 'Error refresh_token is revoked'
    req.status(403).json({status, message})
  }
})

server.use(/^(?!\/auth).*$/,  (req, res, next) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401
    const message = 'Error in authorization format'
    res.status(status).json({status, message})
    return
  }
  try {
     const verify = verifyToken(req.headers.authorization.split(' ')[1])
     if (verify['name']==='TokenExpiredError' || req.headers.authorization.split(' ')[1] === null) {
       throw verify
     }
     console.log('GO TO NEXT', verify)
     console.log('TOKEN1', req.headers.authorization.split(' ')[0])
     console.log('TOKEN2', req.headers.authorization.split(' ')[1])
     next()
  } catch (err) {
    console.log('ERRO DE VALICAO DE TOKEN', err)
    const status = 401
    const message = 'Error access_token is revoked'
    res.status(status).json({status, message})
  }
})

server.use(router)

server.listen(3000, () => {
  console.log('Run Auth API Server')
})