const _sodium = require('libsodium-wrappers');
var myKey = null;

/* Set the module's decryption key */
module.exports.setKey = async function(key)
{
    myKey = key;
}

/* Decrypt the cipher providing a nonce and a key, throws a 'no key' exception when there is no key set */
module.exports.decrypt = async function(ciphertext, nonce)
{
    if (myKey === null)
        throw 'no key';

    /* Wait for sodium to be ready */
    await _sodium.ready;

    /*Use crypto_secretbox_open_easy() to decrypt the ciphertext using the same key and
    nonce. */
    return _sodium.crypto_secretbox_open_easy(ciphertext, nonce, myKey);
}
