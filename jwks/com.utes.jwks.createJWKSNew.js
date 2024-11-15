/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * 
 * 
 */
const jose = require('node-jose');
const fs = require('fs');
const path = require('path');
const keystore = jose.JWK.createKeyStore();
const opts = {
    algorithms: ["RS256"],
};

const privkeys = [
    fs.readFileSync(path.join('./user_certs/karan123456_prvKey.pem')),
    fs.readFileSync(path.join('./user_certs/karan123456_prvKey.pem')),
];


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function creteKeystore() {
    await keystore.add(privkeys[1], 'pem');
    await keystore.add(privkeys[0], 'pem');
}


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function createPublicJWK() {
    const jwk = keystore.toJSON();
    return jwk;
}


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function createPrivateJWK() {
    // giving true as argument will give private JWK
	creteKeystore();
    const jwk = keystore.toJSON(true);
    return jwk;
}


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function createJWT(payload) {
    let token = await jose.JWS
        .createSign({ format: 'compact' }, keystore.all()[0])
        .update(JSON.stringify(payload))
        .final();
    return token;
}


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function verifyJWT(token, jwk) {
    const keystore = await jose.JWK.createKeyStore();
    for (const key of jwk.keys) {
        await keystore.add(key);
    }
    const result = await jose.JWS
        .createVerify(keystore, opts)
        .verify(token);
    return result;
}

exports.creteKeystore = creteKeystore;
exports.createPublicJWK = createPublicJWK;
exports.createPrivateJWK = createPrivateJWK;
exports.createJWT = createJWT;
exports.verifyJWT = verifyJWT;
//var key = createPrivateJWK();
//console.log(JSON.stringify(key));