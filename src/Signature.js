const _sodium = require('libsodium-wrappers');
let keypair = null;

(async () => {
    /* Wait for sodium to be ready */
    await _sodium.ready;
    /*The crypto_sign_keypair() function randomly generates a secret key and a corresponding public key. */
    keypair = _sodium.crypto_sign_keypair();
})();


/* Sign the message with a private key */
module.exports.sign = async function(msg)
{
    await _sodium.ready;

    /* Sign the message -- The crypto_sign() function prepends a signature to a message */
    return _sodium.crypto_sign(msg, keypair.privateKey);
}

/* Return the public key */
module.exports.verifyingKey = async function()
{
    await _sodium.ready;

    return keypair.publicKey;
}