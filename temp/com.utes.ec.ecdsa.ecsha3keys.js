/*
 * blogs: https://linx.software/docs/6/reference/plugins/cryptography/content/createecdsakeys/
 * https://asecuritysite.com/signatures/ecdsa






*/


var elliptic = require('elliptic');
var sha3 = require('js-sha3');
var ec = new elliptic.ec('secp256k1');
var forge = require('node-forge');
var crypto = require("crypto");
const { Buffer } = require('buffer');

var privKey = null;
var pubKey =  null;
var signature = null;
var msgHash = null;

function createECPrivateKey(user, curvType, path) {
  /*
   https://gist.github.com/canterberry/bf190ae6402265751e51725be535a4e4
   How find this numbers:

   1. run openssl ecparam -name prime256v1 -genkey -noout -out key.pem with curve name desired
   2. upload to https://lapo.it/asn1js/ or open with hex editor
   3. find control characters and key blocks (compare lengths with your own key in hex format)
   4. Extract control characters and replace in the code of this git
   5. Generate a pem of test and validate it with the tool of step 2
   6. Repeat steps 3 to 5 while not success
  */
  const keyPair = crypto.createECDH(curvType); // 1. prime256v1, 2. secp256k1

    keyPair.generateKeys();
    // print the PEM-encoded for prime256V1
    var pkey = `-----BEGIN EC PRIVATE KEY-----
    ${Buffer.from(`30770201010420${keyPair.getPrivateKey('hex')}A00A06082A8648CE3D030107A144034200${keyPair.getPublicKey('hex')}`, 'hex').toString('base64')}
    -----END EC PRIVATE KEY-----`;
    console.log("PrivateKey-PEM:   " + pkey);


    // Print the PEM-encoded private key
    console.log(`-----BEGIN PRIVATE KEY-----
    ${Buffer.from(`308184020100301006072a8648ce3d020106052b8104000a046d306b0201010420${keyPair.getPrivateKey('hex')}a144034200${keyPair.getPublicKey('hex')}`, 'hex').toString('base64')}
    -----END PRIVATE KEY-----`);

    // Print the PEM-encoded public key
    console.log(`-----BEGIN PUBLIC KEY-----
    ${Buffer.from(`3056301006072a8648ce3d020106052b8104000a034200${keyPair.getPublicKey('hex')}`, 'hex').toString('base64')}
    -----END PUBLIC KEY-----`);
}

function genKeyPairEcSha3 (type ) {
    // let keyPair = ec.genKeyPair(); // Generate random keys
    var keyPair = ec.keyFromPrivate(
    "97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a");
    privKey = keyPair.getPrivate("hex");
    pubKey = keyPair.getPublic();
    console.log(`Private key: ${privKey}`);
    console.log("Public key :", pubKey.encode("hex").substr(2));
    console.log("Public key (compressed):", pubKey.encodeCompressed("hex"));
    if (type === 'private') {
        return privKey;
    }
    if (type === 'public') {
        return pubKey;
    }
}

function signMsg (msgBuf) {
    var msg = 'Message for signing';
    msgHash = sha3.keccak256(msg);
    signature = ec.sign(msgHash, privKey, "hex", {canonical: true});

    console.log(`Msg: ${msg}`);
    console.log(`Msg hash: ${msgHash}`);
    console.log("Signature:", signature);
    return signature;
}


function verifySignature(sig) {
    var hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
    var pubKeyRecovered = ec.recoverPubKey( hexToDecimal(msgHash), signature, signature.recoveryParam, "hex");
    console.log("Recovered pubKey:",  pubKeyRecovered.encodeCompressed("hex"));
    var validSig = ec.verify( msgHash, signature, pubKeyRecovered);
    console.log("Signature valid?", validSig);
    return validSig;
}


async function crX509CertEcc (type) {
    console.log('Generating 2048-bit key-pair...');
    // var keys = await forge.pki.rsa.generateKeyPair(2048);
    console.log('Key-pair created.');
    // crAns1Eckeys();
    console.log('Creating self-signed certificate...   ' );
    var cert = await forge.pki.createCertificate();
    cert.publicKey = pubKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    var attrs = [{
      name: 'commonName',
      value: 'example.org'
    }, {
      name: 'countryName',
      value: 'US'
    }, {
      shortName: 'ST',
      value: 'Virginia'
    }, {
      name: 'localityName',
      value: 'Blacksburg'
    }, {
      name: 'organizationName',
      value: 'Test'
    }, {
      shortName: 'OU',
      value: 'Test'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    /*
     * cert.setExtensions([{ name: 'basicConstraints', cA: true/* ,
     * pathLenConstraint: 4 }, { name: 'keyUsage', keyCertSign: true,
     * digitalSignature: true, nonRepudiation: true, keyEncipherment: true,
     * dataEncipherment: true }, { name: 'extKeyUsage', serverAuth: true,
     * clientAuth: true, codeSigning: true, emailProtection: true, timeStamping:
     * true }, { name: 'nsCertType', client: true, server: true, email: true,
     * objsign: true, sslCA: true, emailCA: true, objCA: true }, { name:
     * 'subjectAltName', altNames: [{ type: 6, // URI value:
     * 'http://example.org/webid#me' }, { type: 7, // IP ip: '127.0.0.1' }] }, {
     * name: 'subjectKeyIdentifier' }]);
     */
    // FIXME: add authorityKeyIdentifier extension
    console.log('unsigned_cert:    ', cert);
    //var cert_pem = forge.pki.certificateToPem(cert);
    
    // self-sign certificate
    // hints: https://bitcoin.stackexchange.com/questions/66594/signing-transaction-with-ssl-private-key-to-pem
    
    privKey =  await genKeyPairEcSha3('private');
    var privKey1 = Buffer.from(privKey, 'hex').toString('base64');
    var privKey2 = '-----BEGIN EC PRIVATE KEY-----'+'\r\n'
    +privKey1+'\n'
    +'-----END EC PRIVATE KEY-----'+'\n';
    console.log("privatekey:  " + privKey2  + '    pub:    ' +  pubKey);
    var sign = await crypto.createSign('sha512');
    await sign.update(cert.toString());
    var signature = await sign.sign(privKey2, 'utf8');
    console.log('signature_cert:   ', signature);
    console.log('signed_cert:    ', cert);
    
    
    // PEM-format keys and cert
     var pem = {
     //privateKey: forge.pki.privateKeyToPem(keys.privateKey),
     privateKey: prvkey,
     publicKey: pubkey,
     //publicKey: forge.pki.publicKeyToPem(keys.publicKey),
     certificate: cert
     };
        
     console.log('\nKey-Pair:');
     console.log(pem.privateKey);
     console.log(pem.publicKey);
    
     console.log('\nCertificate:' + JSON.stringify(cert));
     console.log(pem.certificate);
    
    // verify certificate
    var caStore = forge.pki.createCaStore();
    caStore.addCertificate(cert);
    try {
      forge.pki.verifyCertificateChain(caStore, [cert],
        function(vfd, depth, chain) {
          if(vfd === true) {
            console.log('SubjectKeyIdentifier verified: ' +
              cert.verifySubjectKeyIdentifier());
            console.log('Certificate verified.');
          }
          return true;
      });
    } catch(ex) {
      console.log('Certificate verification failure: ' +
        JSON.stringify(ex, null, 2));
    }
}



exports.genKeyPairEcSha3 = genKeyPairEcSha3;
exports.verifySignature = verifySignature;
exports.signMsg = signMsg;
exports.crX509CertEcc = crX509CertEcc;
exports.createECPrivateKey = createECPrivateKey;

/*genKeyPairEcSha3('private');
signMsg('My name is Ajeet');
verifySignature();*/
//crX509CertEcc ('');
createECPrivateKey('','prime256v1',''); //// 1. prime256v1, 2. secp256k1
