# react-native-aes

AES encryption/decryption in react native

Supported ciphers: AES-256-CBC

```js
var AES = require('react-native-aes')
var Buffer = require('buffer').Buffer

var stringInput = 'hey ho'
var bufferInput = new Buffer(stringInput)
// sample key
var key = new Buffer('f0ki13SQeRpLQrqk73UxhBAI7vd35FgYrNkVybgBIxc=', 'base64')
var cipherName = 'AES-256-CBC'
AES.encryptWithCipher(
  cipherName,   // String
  bufferInput,  // Buffer (input data)
  key,          // AES key, e.g. 32 bytes of random data
  function (err, encrypted) {
//  "encrypted" is of the form
//  {
//    ciphertext: Buffer,
//    iv: Buffer
//  }
//
//  you'll need both parts to decrypt

    AES.decryptWithCipher(
      cipherName,             // String
      encrypted.ciphertext,   // Buffer (input data)
      key,
      encrypted.iv,           // Buffer
      function (err, plaintext) {
        // plaintext is a Buffer
        if (plaintext.toString() !== stringInput) {
          throw new Error('time to report an issue!')
        }
      }
    )
  }
)
```
