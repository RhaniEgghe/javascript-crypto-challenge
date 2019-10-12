const nacl = require('libsodium-wrappers')
const Signature = require('../src/Signature')

describe('signing module', () => {
  it('provides a verifying key', async () => {
    expect(await Signature.verifyingKey()).toBeDefined()
  })
  it('returns a signed message', async () => {
    const msg = nacl.randombytes_buf(1024)
    const signedMsg = await Signature.sign(msg)
    const verifyingKey = await Signature.verifyingKey()
    expect(nacl.crypto_sign_open(signedMsg, verifyingKey)).toEqual(msg)
  })
})
/*
The crypto_sign_open() function checks that the signed message has a valid signature for the public key.

NaCl (pronounced "salt") is an abbreviation for "Networking and Cryptography library", a public domain "...high-speed software library for network communication, encryption, decryption, signatures, etc".
*/