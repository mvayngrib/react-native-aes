
var { NativeModules } = require('react-native')
var RNAES = NativeModules.RNAES
var Buffer = require('buffer').Buffer
var assert = function (statement, err) {
  if (!statement) throw normalizeError(err || 'assert failed')
}

export function encryptWithCipher (cipherName, data, key, cb) {
  assert(typeof cipherName === 'string', 'expected "String" cipherName')
  assert(Buffer.isBuffer(data), 'expected Buffer "data"')
  assert(Buffer.isBuffer(key), 'expected Buffer "key"')
  assert(typeof cb === 'function', 'expected Function "cb"')
  return RNAES.encryptWithCipher(
    cipherName,
    toBase64String(data),
    toBase64String(key),
    function (err, result) {
      if (err) return cb(normalizeError(err))

      cb(null, {
        ciphertext: toBuffer(result.ciphertext),
        iv: toBuffer(result.iv)
      })
    }
  )
}

export function decryptWithCipher (cipherName, data, key, iv, cb) {
  assert(typeof cipherName === 'string', 'expected "String" cipherName')
  assert(Buffer.isBuffer(data), 'expected Buffer "data"')
  assert(Buffer.isBuffer(key), 'expected Buffer "key"')
  assert(Buffer.isBuffer(iv), 'expected Buffer "iv"')
  assert(typeof cb === 'function', 'expected Function "cb"')
  return RNAES.decryptWithCipher(
    cipherName,
    toBase64String(data),
    toBase64String(key),
    toBase64String(iv),
    function (err, plaintext) {
      if (err) return cb(normalizeError(err))

      cb(null, toBuffer(plaintext))
    }
  )
}

function normalizeError (msg) {
  return msg instanceof Error ? msg : new Error(msg)
}

function toBase64String (buf) {
  return typeof buf === 'string' ? buf : buf.toString('base64')
}

function toBuffer (buf) {
  return Buffer.isBuffer(buf) ? buf : new Buffer(buf, 'base64')
}
