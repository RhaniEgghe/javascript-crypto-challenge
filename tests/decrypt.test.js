const nacl = require('libsodium-wrappers')
const Decryptor = require('../src/Decryptor.js')

describe('decryption module', () => {
/*The let statement declares a block scope local variable, optionally initializing it to a value. */
  let msg, ciphertext, nonce, key

  /*In some cases, you only need to do setup once, at the beginning of a file. 
  This can be especially bothersome when the setup is asynchronous, so you can't just do it inline. 
  Jest provides beforeAll and afterAll to handle this situation. */
  beforeAll(async () => {
    await nacl.ready
    /*Create a secret key using crypto_secretbox_keygen()*/ 
    key = nacl.crypto_secretbox_keygen()
  })


  /*beforeEach and afterEach can handle asynchronous code in the same ways that tests can handle asynchronous code  */
  beforeEach(() => {
    msg = nacl.randombytes_buf(1024)
    nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES)

    /*Use crypto_secretbox_easy() to encrypt the message, and send/store the resulting
      ciphertext along with the nonce. Unlike the key, the nonce doesn't have to be
      secret. 
      
      In cryptography, a nonce is an arbitrary number that can be used just once in a cryptographic communication.

      In cryptography, ciphertext or cyphertext is the result of encryption performed on plaintext using an algorithm, called a cipher.
      */
    ciphertext = nacl.crypto_secretbox_easy(msg, nonce, key)
  })

  it('needs a decryption key before it can decrypt', async () => {
    try {
      await Decryptor.decrypt(ciphertext, nonce)
    } catch (e) {
      expect(e).toMatch('no key')
    }
    Decryptor.setKey(key)
    await Decryptor.decrypt(ciphertext, nonce) // should succeed
  })

  it('decrypts an encrypted message', async () => {
    expect(await Decryptor.decrypt(ciphertext, nonce)).toEqual(msg)
  })
})
