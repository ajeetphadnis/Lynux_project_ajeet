/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * JWT explained in this url below:
 * https://medium.com/nerd-for-tech/jwt-jws-and-jwe-in-nodejs-7595542565d0
 * 
 */
const fs = require('fs');
const fsBase = require('fs');
const path = require('path');
const fsp = fsBase.promises
const jose = require('node-jose');
const forge = require("node-forge");
const {JWK, JWE, parse } = require("node-jose");
const pem = require("pem");



/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
const getCA_P12_PrivKey = async ( uid, filePath, pass ) => {
    // Read file in binary contents
    console.log("loadCA_P12Cert001: " + filePath +  '  ' + pass);
    var p12 = fs.readFileSync(filePath);
    console.log("loadCA_P12Cert002: "+ filePath +  '  ' + pass);
    // const file = fs.readFileSync('file.pfx');
    const p12Der = forge.util.decode64(p12.toString('base64'));
    const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pass);
    const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
		const pemPrivate = forge.pki.privateKeyToPem(key);
		console.log(pemPrivate);
		//DUMP_PRIVATE_KEY = pemPrivate;
		return pemPrivate;
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
const getCA_P12_PubKey = async ( uid, filePath, pass ) => {
    // Read file in binary contents
    console.log("loadCA_P12Cert001: " + filePath);
    var p12 = fs.readFileSync(filePath);
    console.log("loadCA_P12Cert002: "+ filePath +  '  ' + pass);
    // const file = fs.readFileSync('file.pfx');
    const p12Der = forge.util.decode64(p12.toString('base64'));
    const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pass);
    const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
		const pemPublic = forge.pki.publicKeyToPem(key);
		console.log(pemPublic);
		//DUMP_PRIVATE_KEY = pemPrivate;
		return pemPublic;
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
async function genJWK (uid, path, pass) {
  try {
    // keystore to stick our node-jose keys before we do signing 
    let keystore = jose.JWK.createKeyStore();
    //console.log("Prv: " + uid + path);
    // load in the private key
    var privatepem = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
    var privatekey = await keystore.add(privatepem, 'pem');
    console.log("privatekey:  " + JSON.stringify(privatekey));
    // and the public key
    var pubkey = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
    //console.log("pubkey:  " + pubkey);
    let publicpem = fs.readFileSync('./user_certs/karan123456_selfsigned.crt', 'utf8')
    //let publicpem = fs.readFileSync('./device.crt', 'utf8')
    let publickey = await keystore.add(publicpem, 'pem');
    console.log("pubkey:  " + pubkey);
    console.log("publickey:  " + JSON.stringify(publickey));
    console.log("publicpem:  " + publicpem);
    console.log("ks:  " + JSON.stringify(keystore));
    // we need the public key chain in x5c header. x5c header chain will be used during
    // decode, a full cert can be provided to ensure validation all the way to root
    // https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#page-9
    // unfortunately we can't just use plain jwk, since jwk is only the *key* and not the
    // full *certificate*, so ... x5c it is
    let x5cChain = cert_to_x5c(publicpem);
    console.log("x5cChain:  " + x5cChain);
    // the message body
    let message = JSON.stringify({
      iss: 'vendor',
      sub: '1234',
      exp: Date.now()+10*60*1000, // expires in 10 minutes
      iat: Date.now(),
      bundle: '...'
    });

    // and signing options
    let signoptions = { fields: { x5c: x5cChain } }

    // sign 'message' with the 'privatekey', include the 'x5c' chain in the headers
    var signed;
    await jose.JWS.createSign(signoptions, privatekey).update(message, 'utf8').final().then( function(result) {
     // bet you didn't think it would be that big
    	console.log("Result:   " + JSON.stringify(result));
    	signed = result;});

    console.log('Junst//////////////////////////////');

    // a quick sanity check - the cisco/node-jose lib provides x5c verification fortunately
    let result = await jose.JWS.createVerify(keystore).verify(signed);
    console.log("expiration data:   " );
    //console.log(JSON.parse(result.payload));
    //console.log(JSON.parse(result.header));
    console.log('Ajeet //////////////////////////////');
    console.log("expiration data:   " );
    // but .. it doesn't check expiry date on the message
    let exp = new Date(JSON.parse(result.payload).exp);
    console.log("expiration data:   " + exp);
    if (Date.now() > exp) {
      console.log('message is too old');
      throw Error(`message expiry [exp] is too old; JWS expires at: ${exp}`);
    } else {
      console.log('message expiry valid');
    }

    // and .. it doesn't do the full x509 cert verification, it just checks that the
    // key from the first cert in the x5c header can verify the payload so now, we
    // need to shell out to openssl to verify that the provided key was signed by the CA
    // why oh why is there nothing native for this
    let cert = await x5c_to_cert(result.header.x5c);
    console.log("x5c:  " + cert);
    // load the CA
    let cacert = fs.readFileSync('./user_certs/karan123456_selfsigned.crt', 'utf8');
    console.log('cacert:   ', cacert);
    // it actually works!
    let trusted = await verifySigningChain(cert, cacert);

    console.log('worked?', trusted);
    console.log(JSON.parse(result.payload));
    console.log(JSON.parse(JSON.stringify(signed)));
  } catch (err) {
    console.log(err);
  }
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
// promisify the thing
function verifySigningChain (cert, cacert) {
  return new Promise((resolve, reject) => {
    pem.verifySigningChain(cert, cacert, (err, ver) => {
      if (err) return reject(err);
      return resolve(ver);
    });
  });
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
// taken from (MIT licensed):
// https://github.com/hildjj/node-posh/blob/master/lib/index.js
function cert_to_x5c (cert, maxdepth) {
  if (maxdepth == null) {
    maxdepth = 0;
  }
  /*
   * Convert a PEM-encoded certificate to the version used in the x5c element
   * of a [JSON Web Key](http://tools.ietf.org/html/draft-ietf-jose-json-web-key).
   *             
   * `cert` PEM-encoded certificate chain
   * `maxdepth` The maximum number of certificates to use from the chain.
   */

  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '');
  cert = cert.replace(/(\r\n|\n|\r)/gm, "");
  cert = cert.split(',').filter(function(c) {
    return c.length > 0;
  });
  if (maxdepth > 0) {
    cert = cert.splice(0, maxdepth);
  }
  return cert;
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
function x5c_to_cert (x5c) {
  var cert, y;
  cert = ((function() {
    var _i, _ref, _results;
    _results = [];
    for (y = _i = 0, _ref = x5c.length; _i <= _ref; y = _i += 64) {
      _results.push(x5c.slice(y, +(y + 63) + 1 || 9e9));
    }
    return _results;
  })()).join('\n');
  return ("-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----");
}


exports.genJWK = genJWK;

//genJWK('karan123456', './user_certs/', 'password');