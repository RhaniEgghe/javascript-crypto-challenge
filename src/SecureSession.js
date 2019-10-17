const _sodium = require('libsodium-wrappers');
var rx = null;
var tx = null;
var privateKey = null;
var publicKey = null;
var clientKey = null;

module.exports.setClientPublicKey = function(key)
{
    /* Our key is already set */
    if (clientKey === key)
        return;

    /* Do not allow key modification */
    if ((clientKey !== null) && (clientKey !== key))
        throw 'client public key already set';

    clientKey = key;

    /* Generate server key exchange keypair */
    const keypair = _sodium.crypto_kx_keypair();
    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;

    /* Generate shared keys */
    sharedKeys = _sodium.crypto_kx_server_session_keys(publicKey,privateKey,key);  
    
    /* Set rx (shared secret key) & tx  send data and receive data */
     /*The crypto_kx_server_session_keys() function computes a pair of shared keys (rx and tx) using 
        the server's public key server_pk, 
        the server's secret key server_sk and 
        the client's public key client_pk.*/
    /*It returns 0 on success, or -1 if the server's public key is not acceptable.*/
    /* The shared secret key rx should be used by the server to receive data from the client, (by the server from client)
        whereas tx should be used for data flowing in the opposite direction.                  (by the client from server)*/
    rx = sharedKeys.sharedRx;
    tx = sharedKeys.sharedTx;
}

module.exports.serverPublicKey = async function()
{
    /* Wait for sodium to be ready */
    await _sodium.ready;

    /* Return public key */
    return publicKey;
}

module.exports.encrypt = async function(msg)
{
    /* Wait for sodium to be ready */
    await _sodium.ready;

    /* Generate nonce & encrypt */
    nonce = _sodium.randombytes_buf(_sodium.crypto_secretbox_NONCEBYTES)
    ciphertext = _sodium.crypto_secretbox_easy(msg, nonce, tx)

    /* Return cipher & nonce */
    return { ciphertext, nonce }
}

module.exports.decrypt = async function(ciphertext, nonce)
{
    /* Wait for sodium to be ready */
    await _sodium.ready;

    /* Decrypt the message given then cipher & nonce, encoder */
    return await _sodium.crypto_secretbox_open_easy(ciphertext, nonce, rx)
}
