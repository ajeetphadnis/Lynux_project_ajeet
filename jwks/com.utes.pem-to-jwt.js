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
require('dotenv').config();
const jwtHeler = require("./com.utes.jwks.createJWKSNew");
const fs = require('fs');
const fsps = fs.promises;
var forge = require('node-forge');
var cn, nbfv, naf;
const payload = {
        'iss': 'idp.utes.com', 'sub': '', 'aud': 'https://utes.com/saml', 'nbf': '', 'iat': '', 'exp': '' };
var prvtKey;


var debug = process.env.DEBUG23;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
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
const readFile = (filePath, encoding) => {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, encoding, (err, data) => {
            if (err) {
                return reject(err);
            }
            resolve(data);
            console.log("readFile001:     " + data.toString());
            return data.toString();
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
async function getCA_P12_PrivateKey ( uid, filePath, pass ) {
    // Read file in binary contents
    console.log("loadCA_P12Cert001: "+ filePath +  '  ' + pass);
    var p12 = await readFile(filePath, 'utf8');
    await jwtHeler.createKeystore(p12);
//    console.log("loadCA_P12Cert002: " + p12);
//    // const file = fs.readFileSync('file.pfx');
//    const p12Der = forge.util.decode64(p12.toString('base64'));
//    const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
//    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pass);
//    const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
//		const pemPrivate = forge.pki.privateKeyToPem(key);
		console.log(p12);
		prvtKey = p12;
//		//DUMP_PRIVATE_KEY = pemPrivate;
		return p12;
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
async function getX509Details (uid, filePath, pass) {
    var pem = null;
    console.log("getX509Details:001:    " + uid + "     :   file:    " + filePath + "      :pass:     " + pass );
    if (pem === null || pem === 'undefined') {
	pem =  await readFile(filePath, 'utf8');
	console.log('getX509Details:0011   ' + pem);
	
	const cert = forge.pki.certificateFromPem(pem);
	var caStore = forge.pki.createCaStore(cert);
	var issuer_ou = cert.issuer.getField('OU').value;
	var issuer_o = cert.issuer.getField('O').value;
	var naf = cert.validity.notAfter;
	var date = new Date(naf);
	var seconds = date.getTime() / 1000; // 1440516958
	payload.iat = seconds+36000;
	payload.exp = seconds+36000;
	console.log("getX509Details002:  " + naf + "       " + seconds); 
	var nbfv = cert.validity.notBefore;
	console.log(nbfv);
	var date = new Date(nbfv);
	seconds = date.getTime() / 1000; // 1440516958
	payload.nbf = seconds+36000;
	console.log("getX509Details003:  " + nbfv + "       " + seconds);
	console.log(cert.serialNumber);
	payload.sub = cert.subject.getField('CN').value;
	var cn = cert.subject.getField('CN').value;
	console.log("getX509Details004:  " + cn);
	console.log("getX509Details005:  " + issuer_ou);
	console.log("getX509Details006:  " + issuer_o);
	console.log("getX509Details007:  " + JSON.stringify(payload));
	return payload;
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
async function cre_pem2jwt(uid, prvKeyFile, pubCertFile, pass, paydata) {
	await getX509Details (uid, pubCertFile, pass);
//    const payload = {
//        msg: "Hello!"
//    };
    await jwtHeler.creteKeystore();
    const publicJWK = await jwtHeler.createPublicJWK();
    const privateJWK = await jwtHeler.createPrivateJWK();
    const token = await jwtHeler.createJWT(payload);
    const result = await jwtHeler.verifyJWT(token, publicJWK);
    
    if(debug) {console.log("public jwk :: ", JSON.stringify(publicJWK));}
    console.log("\n");
    if(debug) {console.log("private jwk :: ", JSON.stringify(privateJWK));}
    console.log("\n");
    if(debug) {console.log("token :: ", token);}
    fs.writeFile('./user_certs/'+uid+'_pem2jwks.jwt', token, function(err) {
		if(err) {
	        return console.log(err);
	    }
		return token;
    });
    console.log("\n");
    if(debug) {console.log("payload :: ", result.payload.toString());}

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
async function cre_demopem2jwt(uid, prvKeyFile, pubCertFile, pass, paydata) {
	await getX509Details (uid, pubCertFile, pass);
//    const payload = {
//        msg: "Hello!"
//    };
    await jwtHeler.creteKeystore();
    const publicJWK = await jwtHeler.createPublicJWK();
    const privateJWK = await jwtHeler.createPrivateJWK();
    const token = await jwtHeler.createJWT(payload);
    const result = await jwtHeler.verifyJWT(token, publicJWK);
    
    if(debug) {console.log("public jwk :: ", JSON.stringify(publicJWK));}
    console.log("\n");
    if(debug) {console.log("private jwk :: ", JSON.stringify(privateJWK));}
    console.log("\n");
    if(debug) {console.log("token :: ", token);}
    fs.writeFile('./demo_certs/'+uid+'_pem2jwks.jwt', token, function(err) {
		if(err) {
	        return console.log(err);
	    }
		return token;
    });
    console.log("payload :: ", result.payload.toString());
    if(debug) {console.log("payload :: ", result.payload.toString());}

}
exports.cre_pem2jwt = cre_pem2jwt;
exports.cre_demopem2jwt = cre_demopem2jwt;
exports.getX509Details = getX509Details;
exports.getCA_P12_PrivateKey = getCA_P12_PrivateKey;
//getCA_P12_PrivateKey ( 'karan123456', './user_certs/karan123456_prvKey.pem', 'password' );
//getX509Details ('karan123456', './user_certs/karan123456_selfsigned.crt', 'password');
//cre_pem2jwt('karan123456', './user_certs/karan123456_prvKey.pem', './user_certs/karan123456_selfsigned.crt', 'password', payload, '', '', '');
//getX509Details ('kunalpandya','./user_certs/kunalpandya_selfsigned.crt', 'kunalpandya') ;
//cre_demopem2jwt('yogesh', './demo_certs/yogesh_prvKey.pem', './demo_certs/yogesh_selfsigned.crt', 'yogesh', payload,)
