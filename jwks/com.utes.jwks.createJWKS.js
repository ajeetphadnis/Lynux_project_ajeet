/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On: http://usejsdoc.org/ This module is a utility for generating jwks
 * and endpoints for jwk verifier for clients This module is based on:
 * https://sometimes-react.medium.com/jwks-and-node-jose-9273f89f9a02 A good
 * explaination is in link below:
 * https://medium.com/nerd-for-tech/jwt-jws-and-jwe-in-nodejs-7595542565d0
 */
require('dotenv').config();
const fs = require('fs');
const fsBase = require('fs');
const path = require('path');
const fsp = fsBase.promises
const jose = require('node-jose');
const forge = require("node-forge");
const {JWK, JWE, parse } = require("node-jose");
const { generateKeyPair, createPublicKey } = require('crypto'); // native
const Users =  require("../models/com.utes.auth.users");
var pemJWKS = require('./com.utes.pem-to-jwt');
/**
 * const pem2jwk = require("./com.utes.pem-to-jwks"); you don’t need to add null
 * and ‘empty-space’ as 2nd and 3rd argument for the JSON stringify but I really
 * like to keep my files readable for the human eye, and I’m passing the true to
 * the toJSON(true) method, because this flag will return the public but also
 * the private section of the asymmetric key and we will use the private key
 * later to sign the token
 * 
 * @returns
 */
var keyStore = '';

	var newuser = new Users ({
		  nameIdentifier: '',
		  emailAddress: '',
		  fullname: '',
		  commonName: '',
		  orgName: '',
		  password: '',
		  mobilePhone: '',
		  groups: '',
	});

	user = {
		uid: '',
		pass: '',
		serv: '',
		srctxt: '',
		destxt: '',
		jwksets: '',
		oprf: '',
		oprt: '',
		newuser: {}
	};
	
	var debug = process.env.DEBUG20;
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
            if(debug) {console.log(data.toString());}
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
const getCA_P12_PrivKey = async ( uid, filePath, pass ) => {
    // Read file in binary contents
    if(debug) {console.log("loadCA_P12Cert001: " + pass);}
    var p12 = fs.readFileSync(filePath);
    console.log("loadCA_P12Cert002:prv: "+ filePath +  '  ' + pass);
    // const file = fs.readFileSync('file.pfx');
    const p12Der = forge.util.decode64(p12.toString('base64'));
    const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pass);
    const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
		const pemPrivate = forge.pki.privateKeyToPem(key);
		if(debug) {console.log(pemPrivate);}
		// DUMP_PRIVATE_KEY = pemPrivate;
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
    if(debug) {console.log("loadCA_P12Cert001: " + pass);}
    var p12 = fs.readFileSync(filePath);
    console.log("loadCA_P12Cert002:pub: "+ filePath +  '  ' + pass);
    // const file = fs.readFileSync('file.pfx');
    const p12Der = forge.util.decode64(p12.toString('base64'));
    const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pass);
    const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
		const pemPublic = forge.pki.publicKeyToPem(key);
		if(debug) {console.log(pemPublic);}
		// DUMP_PRIVATE_KEY = pemPrivate;
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
function cert_to_x5c (cert, maxdepth) {
	if(debug) {console.log("Cert1:  " + cert);}
      if (maxdepth == null) {
        maxdepth = 0;
      }
      /*
	 * Convert a PEM-encoded certificate to the version used in the x5c
	 * element of a [JSON Web
	 * Key](http://tools.ietf.org/html/draft-ietf-jose-json-web-key).
	 * 
	 * `cert` PEM-encoded certificate chain `maxdepth` The maximum number of
	 * certificates to use from the chain.
	 */
      cert = cert.toString();
  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '');
  cert = cert.split(',').filter(function(c) {
      return c.length > 0;
  });
  if (maxdepth > 0) {
    cert = cert.splice(0, maxdepth);
  }
  if(debug) {console.log("Cert2:  " + cert);}
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
async  function createstdJWKStore (uid, path, pass) {
		var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
		// var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
		// var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
		console.log("createstdJWKStore001: " + uid + "    " + path + "    " + pass);
		var pubk = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
		const jwKeys = await Promise.all([
	        JWK.asKey(prvKey, "pem"),
	        JWK.asKey(pubk, "pem")
	    ]);
	    let keystore = JWK.createKeyStore();
	    await keystore.add(jwKeys[0]);
	    await keystore.add(jwKeys[1]);
		// keyStore.then(result => {
		  fs.writeFileSync('./JWKSets/'+uid+'_stdjwks.json', JSON.stringify(keystore.toJSON(true), null, '  '));
		// });
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
async function getJWKStore (uid, path, req, res, next)  {
	console.log("getJWKStore001: " + uid + "    " + path );
	  const {promises: {readFile}} = require("fs");
	  readFile(path+uid+'_pem2jwks.json').then(fileBuffer => {
	    // console.log(fileBuffer.toString());
		  var keystore = jose.JWK.asKeyStore(fileBuffer.toString());
		  keyStore = fileBuffer.toString();
		if(debug) {console.log("Ajeet:  " + keyStore);}
		keyStore = keystore;
		return keystore;
	  }).catch(error => {
	    console.error(error.message);
	    process.exit(1);
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
	async function loadKeyStore1(req, res) {
	    const data = await fs.readFile('./JWKSets/keys.json');
	    var keystore = jose.JWK.asKeyStore(data.toString());
	    if(debug) {console.log("Ajeet:  " + data);}
	    return new Buffer(keystore);
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
	const loadKeyStore = async (uid, path, req, res, next) => {
		console.log("loadKeyStore001: " + uid + "    " + path );
		const data = await fsp.readFile(path);
	    // console.log(data.toString());
	    var keys = await jose.JWK.asKeyStore(data.toString()).
	     then(function(result) {
	    	 if(debug) {console.log(keys);}
	       // {result} is a jose.JWK.KeyStore
	       keyStore = result;
	       if(debug) {console.log(JSON.stringify(result));}
	       return keyStore;
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
	// This function is used by /jwks endpoint.
	const getJWKPublic = async (uid, path, req, res, next) => {
		console.log("getJWKPublic001: " + uid + "    " + path );
		const ks = fs.readFileSync(path+uid+'_pem2jwks.json');
		const keyStore = await jose.JWK.asKeyStore(ks.toString());
		return (keyStore.toJSON());
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
	const createJWToken1 = async (uid, path, req, res, next) => {
		var key = fs.readFileSync(path+uid+'_prvKey.pem');

		var serviceAccountId = uid;
		var keyId = '0987654321';
		var now = Math.floor(new Date().getTime() / 1000);

		var payload = { aud: "https://iam.api.cloud.yandex.net/iam/v1/tokens",
		                iss: serviceAccountId,
		                iat: now,
		                exp: now + 3600 };

		jose.JWK.asKey(key, 'pem', { kid: keyId, alg: 'RS256' })
		    .then(function(result) {
		        jose.JWS.createSign({ format: 'compact' }, result)
		            .update(JSON.stringify(payload))
		            .final()
		            .then(function(result) {
		                // result
		            	if(debug) {console.log("Result: " + result);}
		            	fs.writeFileSync('./user_jwtokens/'+uid+"_jwtok.jwt", result, null, '  ');
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
	async function createJWKStore (uid, path, pass, req, res, next) {
		console.log("createJWKStore001: " + uid + "    " + path );
		const keyStore = jose.JWK.createKeyStore();
		console.log("createJWKStore:001");
		var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
		// var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
		// var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
		var pubk = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
		const jwKeys = await Promise.all([
	        JWK.asKey(prvKey, "pem"),
	        JWK.asKey(pubk, "pem")
	    ]);
	    // let keystore = JWK.createKeyStore();
	    await keyStore.add(jwKeys[0]);
	    await keyStore.add(jwKeys[1]);
	    console.log("createJWKStore:001");
		fs.writeFileSync('./JWKSets/'+uid+'_pem2jwks.json', JSON.stringify(keyStore.toJSON(true), null, '  '));
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
	async  function createstdJWKStore (uid, path, pass) {
		console.log("createstdJWKStore001: " + uid + "    " + path );
		var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
		// var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
		// var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
		var pubk = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
		const jwKeys = await Promise.all([
	        JWK.asKey(prvKey, "pem"),
	        JWK.asKey(pubk, "pem")
	    ]);
	    let keystore = JWK.createKeyStore();
	    await keystore.add(jwKeys[0]);
	    await keystore.add(jwKeys[1]);
		// keyStore.then(result => {
		  fs.writeFileSync('./JWKSets/'+uid+'_stdjwks.json', JSON.stringify(keystore.toJSON(true), null, '  '));
		// });
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
	 async function x5jwtsjson (uid, path, pass) { 
		console.log("x5jwtsjson001: " + uid + "    " + path );
		 var cert = await fs.readFileSync('./demo_certs/'+uid+'_selfsigned.crt');
		 console.log("x5jwtsjson002: ");
		 // derCrt = await fs.readFileSync('./CERTIFICATE.der');
		 // derCrt = derCrt.toString().replace('r ' , '');
		 cert = cert.toString();
		 cert1 = cert.replace('-----BEGIN CERTIFICATE-----\r\n', '');
		 cert1 = cert1.replace('\r\n-----END CERTIFICATE-----\r\n', '');
		 cert1 = cert1.replace(/(\r\n|\n|\r)/gm, "");
		 // console.log("Cert1: " + cert);;
		 var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
			// var pubKey =
			// fs.readFileSync(path+uid+'_selfsigned.crt');
			// var pubKey = readFile(path+uid+'_selfsigned.crt',
			// 'utf-8');
			var pubk = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
			console.log("x5jwtsjson003: ");
			const jwKeys = await Promise.all([
		        JWK.asKey(prvKey, "pem"),
		        JWK.asKey(pubk, "pem"),
		        ]);
				console.log("x5jwtsjson004: ");
		    let keystore = JWK.createKeyStore();
			console.log("x5jwtsjson005: ");
		    await keystore.add(jwKeys[0]);
		    await keystore.add(jwKeys[1]);
		    await keystore.add(cert, 'pem');
			console.log("x5jwtsjson006: ");
		    var kdata = JSON.stringify(keystore);
		    var pdata = JSON.parse(kdata);
		    pdata.keys[2]['x5c'] = [cert1];
		    JSON.stringify(pdata);
		    // await keystore.add(derCrt, 'x509');
		    if(debug) {console.log("key:  " + JSON.stringify(pdata));}
			console.log("x5jwtsjson007: ");
		    fs.writeFileSync('./JWKSets/'+uid+'_x5cjwks.json', JSON.stringify(pdata), null, '  ');
			console.log("x5jwtsjson008: ");
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
	// This function is used by /token endpoint
		const createJWToken = async (uid, path, req, res, next) => {
			console.log("createJWToken001: " + uid + "    " + path );
			const ks = fs.readFileSync('./JWKSets/'+uid+'_pem2jwks.json');		
			const keyStore = await jose.JWK.asKeyStore(ks.toString());
			const [key] = keyStore.all({ use: 'sig' });		  
			const opt = { compact: true, jwk: key, fields: { algorithms: 'RSA', typ: 'jwt' } }
			const payload = JSON.stringify({
				exp: Math.floor((Date.now() +24*60*60*1000) / 1000),
				iat: Math.floor(Date.now() / 1000),
				sub: 'Ajeet',
			 });
			  const token = await jose.JWS.createSign(opt, key).update(payload, "utf8").final();
			  // res.send({ token })
			  fs.writeFileSync('./user_jwtokens/'+uid+"_jwtok.jwt", token, null, '  ');
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
		// This function is used by /validateToken endpoint
		const validateToken = async (path, req, res) => {
			const { token } = req.body;
			const { data } = await axios.get('http://localhost:4040/jwks');
			const [ firstKey ] = data.keys;
			const publicKey = jwktopem(firstKey);
			try {
				const decoded = jwt.verify(token, publicKey)
			    res.send(decoded)
			} catch (e) {
			    res.send({ error: e })
			}
		}
		
		// This function able to sign JWTs with a different
		// key but also allow the clients that have previously
		// signed JWTs to verify with the help of the /jwks
		// endpoint and after all the clients can’t possibly
		// have an old token (after 24h given the expiration
		// time that we set) we will delete the unused key
		// used by /addKey endpoint
		/**
		 * 
		 * 
		 * 
		 * 
		 * @param firstname
		 * @returns
		 * 
		 */
		const addJWK2KeyStore = async (path, req, res) => {
			console.log("addJWK2KeyStore001: " + uid + "    " + path );
			const ks = fs.readFileSync(path);
			const keyStore = await jose.JWK.asKeyStore(ks.toString());
			await keyStore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' });
			const json = keyStore.toJSON(true);
			json.keys = json.keys.reverse();
			fs.writeFileSync('keys.json', JSON.stringify(json, null, '  '));
		}
		
		// This function now implements the delete key portion
		// (we should trigger that after the maximum time
		// that we apply to the tokens in our case 24h)
		// all we need is plain JS but I’ll use a little
		// bit of node-jose just to return the result and
		// check that is working. Used by /delKey endpoint.
		
		
		/**
		 * 
		 * 
		 * 
		 * 
		 * @param firstname
		 * @returns
		 * 
		 */
		const delJWKFromKeyStore = async (path, req, res) => {
			//console.log("getJWKStore001: " + uid + "    " + path );
			const ks = JSON.parse(fs.readFileSync(path));
			if (ks.keys.length > 1) ks.keys.pop();
			fs.writeFileSync('keys1.json', JSON.stringify(ks, null, '  '));
			const keyStore = await jose.JWK.asKeyStore(JSON.stringify(ks));
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
		const crJWKFromPrivateKeyPEM1 = async (uid, path, req, res, next) => {
			// const prvKey = fs.readFileSync(path);
			// const prvKey = readFile(path, '');
			// Parse PEM-encoded key to RSA public / private JWK
			// var jwkk = JWK.parseFromPEMEncodedObjects(prvKey);
			// console.log(JSON.stringify(jwkk));
			console.log("crJWKFromPrivateKeyPEM1001: " + uid + "    " + path );
			pem2jwk.pem2jwks(uid,  path+uid+'_selfsigned.crt', 'password', req, res, next);
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
		// function does not work.
		const crJWKFromPrivateKeyPEM = async (uid, path, pass, req, res, next) => {
			var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
			// var pubKey =
			// fs.readFileSync(path+uid+'_selfsigned.crt');
			// var pubKey = readFile(path+uid+'_selfsigned.crt',
			// 'utf-8');
			var pubKey = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
			// Parse PEM-encoded key to RSA public / private JWK
			var jwkk = JWK.parseFromPEMEncodedObjects(prvKey);
			if(debug) {console.log(JSON.stringify(jwkk));}
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
		// good examples:
		// https://stackoverflow.com/questions/48659883/how-to-generate-encrypted-jwe-with-node-jose
		// follow this example:
		// https://techdai.info/how-to-create-and-verify-jwt-tokens-via-jwk-endpoints-for-your-microservices-in-node-js/
		// https://techdai.info/how-to-create-and-verify-jwt-tokens-via-jwk-endpoints-for-your-microservices-in-node-js/
		// https://sometimes-react.medium.com/jwks-and-node-jose-9273f89f9a02
		// Implemented code from below link:
		// https://medium.com/nerd-for-tech/jwt-jws-and-jwe-in-nodejs-7595542565d0
		var encrypt = async (raw, pubk, format = 'compact', contentAlg = "A256GCM", alg = "RSA-OAEP") => {	    
		    let publicKey = await JWK.asKey(pubk, "pem");
		    const buffer = Buffer.from(JSON.stringify(raw))
		    const encrypted = await JWE.createEncrypt({ format: format, contentAlg: contentAlg, fields: { alg: alg } }, publicKey)
		        .update(buffer).final();
		    return encrypted;
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
		var decrypt = async (encryptedBody, prvk) => {
		    // let _privateKey =
		    let keystore = JWK.createKeyStore();
		    await keystore.add(await JWK.asKey(prvk, "pem"));
		    let outPut = parse.compact(encryptedBody);
		    let decryptedVal = await outPut.perform(keystore);
		    let claims = Buffer.from(decryptedVal.plaintext).toString();
		    return claims;
		}
		
		
		
		/**
		 * 
		 * 
		 * 
		 * 
		 * @param firstname
		 * @returns JWE is the standard way of encrypting claims of the
		 *          JWT token. The code segments explain how to load
		 *          keys, encrypt the token, and decrypt the token.
		 *          These codes are written in node js using the cisco
		 *          node-jose library. The node-jose library provides a
		 *          JWK namespace to generate, import, and export keys.
		 *          In this example, an asymmetric key pair is used to
		 *          encrypt the payload. Key pairs are generated for any
		 *          logged-in user already.
		 */
		
		const crJWEToken = async (uid, pass, path, req, res, next) => {
			console.log("crJWEToken001: " + uid + "    " + path );
			// var prvKey = fs.readFileSync(path+uid+'_prvKey.pem');
			var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
			// var pubKey =
			// fs.readFileSync(path+uid+'_selfsigned.crt');
			// var pubKey = readFile(path+uid+'_selfsigned.crt',
			// 'utf-8');
			var pubk = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
			const jwKeys = await Promise.all([
		        JWK.asKey(prvKey, "pem"),
		        JWK.asKey(pubk, "pem")
		    ]);
		    let keystore = JWK.createKeyStore();
		    await keystore.add(jwKeys[0]);
		    await keystore.add(jwKeys[1]);
			let raw = {
				    "mobileNumber": "1234567890",
				    "customerId": uid,
				    "sessionId": "3a600342-a7a3-4c66-bbd3-f67de5d7096f",
				    "exp": 1645544094,
				    "jti": "f3902a08-0e24-4dcc-bed1-f4cd9611bfad"
				};
				var encJwe = await encrypt(raw, pubk);
				// var encJwe = await encrypt(raw, prvKey);
				if(debug) {console.log("Encrypted JWE:  " + encJwe);}
				var decJwe = await decrypt(encJwe, prvKey);
				// var decJwe = await decrypt(encJwe, pubk);
				if(debug) {console.log("Decrypted JWE:  " + decJwe);}
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
	// Helper
	// taken from (MIT licensed):
	// https://github.com/hildjj/node-posh/blob/master/lib/index.js
	function cert_to_x5c (cert, maxdepth) {
		if(debug) {console.log("Cert1:  " + cert);}
	  if (maxdepth == null) {
	    maxdepth = 0;
	  }
	  /*
	     * Convert a PEM-encoded certificate to the version used in the x5c
	     * element of a [JSON Web
	     * Key](http://tools.ietf.org/html/draft-ietf-jose-json-web-key).
	     * 
	     * `cert` PEM-encoded certificate chain `maxdepth` The maximum
	     * number of certificates to use from the chain.
	     */
	  cert = cert.toString();
	  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '');
	  cert = cert.split(',').filter(function(c) {
	    return c.length > 0;
	  });
	  if (maxdepth > 0) {
	    cert = cert.splice(0, maxdepth);
	  }
	  if(debug) {console.log("Cert2:  " + cert);}
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
	 async function jwtsjson (uid, path, pass) {
		console.log("jwtsjson001: " + uid + "    " + path );
		 var cert = await fs.readFileSync('./user_certs/karan123456_selfsigned.crt');
		 cert = cert.toString();
		 cert1 = cert.replace('-----BEGIN CERTIFICATE-----', '');
		 cert1 = cert1.replace('-----END CERTIFICATE-----', '');
		 // console.log("Cert1: " + cert);;
		 var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
			// var pubKey =
			// fs.readFileSync(path+uid+'_selfsigned.crt');
			// var pubKey = readFile(path+uid+'_selfsigned.crt',
			// 'utf-8');
			var pubk = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
			const jwKeys = await Promise.all([
		        JWK.asKey(prvKey, "pem"),
		        JWK.asKey(pubk, "pem"),
		        ]);
		 // console.log("Cert1: " + cert);
		 const keystore = jose.JWK.createKeyStore();
		 const output = keystore.toJSON();
		 keystore.toJSON(true);

		 jose.JWK.asKeyStore(keystore).then(result => { 
			 keystore.add(jwKeys[0]);
			 keystore.add(jwKeys[1]);
			 keystore.add(cert, 'pem');
			 if(debug) {console.log("keystore:  " + JSON.stringify(result));}
		 });

		 let key = keystore.get('kid');

		 key = keystore.get('kid', { kty: 'RSA' });

		 // ... and by 'use'
		 key = keystore.get('kid', { use: 'enc' });

		 // ... and by 'alg'
		 key = keystore.get('kid', { alg: 'RSA-OAEP' });

		 // ... and by 'kty' and 'use'
		 key = keystore.get('kid', { kty: 'RSA', use: 'enc' });

		 // same as above, but with a single {props} argument
		 key = keystore.get({ kid: 'kid', kty: 'RSA', use: 'enc' });

		 let everything = keystore.all();

		 // filter by 'kid'
		 everything = keystore.all({ kid: 'kid' });

		 // filter by 'kty'
		 everything = keystore.all({ kty: 'RSA' });
			 
	 }
	 
	 
	 async function getDemoUserJWKSets(req, res, next) {
		 jwksPath = process.env.JWKS_ClientPath;
		 modelPath = process.env.Models_ClientPath;
		 try {
				if (req.method === 'GET' && req.method !== 'POST') {
					console.log('GET');
					req.on('data', function (chunk) {
				        if(debug) {console.log('GET DATA!' + JSON.stringify(data));}
				    });
				}				
				if (req.method === 'POST' && req.method !== 'GET') {
					console.log('POST');
					if(debug) {console.log('Got body:', req.body);}
					if(req.body.udata) {
						var udat = JSON.parse(JSON.stringify(req.body.udata));
						JSON.parse(udat, (key, value) => {
							  if (typeof value === 'string') {
							    console.log("key:  " + key + "  value:  " + value);
							    if(key === 'uid') user.uid = value;
							    if(key === 'ope') user.oprf = value;
							    if(key === 'upass') 
								user.pass = value;
							  }
							  //return value;
							  user.serv = user.oprf;
						});
						console.log("getDemoUserSAMLAsser001:   called ...." + user.uid);
						user.newuser = new Users();
						user.newuser.nameIdentifier = user.uid;
						user.newuser.password = user.pass;
						user.newuser.commonName = 'utesdemo.com';
						user.newuser.orgName = 'utesdemo.com';
						 //ksVals.CustomerId =  user.uid;
						 uid = user.uid;
						 console.log("getJWKS:POST:  " + uid);
						pemJWKS.cre_demopem2jwt (uid, './demo_certs/'+uid+'_prvKey.pem', './demo_certs/'+uid+'_selfsigned.crt', user.pass, '');
						await createstdJWKStore(uid, './demo_certs/', user.pass);
				 		await x5jwtsjson(uid,'./demo_certs/', user.pass);
					 	//ksVals.CustomerId =  req.app.session.clnt;
						 console.log("getDemoUserJWKSets:Post: 001:  ");
						 // new
				 		var xks = fs.readFileSync('./JWKSets/'+uid+'_x5cjwks.json').toString('utf8');
						// console.log("getDemoUserJWKSets:Post 002:   " +xks);
				 		var stdks = fs.readFileSync('./JWKSets/'+uid+'_stdjwks.json').toString('utf8');
						//console.log("getDemoUserJWKSets:Post 003:  " + stdks);
				 		user.jwkstdsets = JSON.parse(stdks);
				 		//user.jwkstdsets = stdks;
						//console.log("getDemoUserJWKSets:Post 004:  " + JSON.stringify(user.jwkstdsets));
				 		user.jwkx5csets = JSON.parse(xks);
				 		//user.jwkx5csets = xks;
				 		//console.log("getDemoUserJWKSets:Post 005:   " + JSON.stringify(user.jwkx5csets));
				 		await res.status(200).send({ user: user});
					}				
				}
//			 		res.render('../views/client_jwks',
//							{
//							    ksVals
//							});
			} catch (err) {
				console.log(err);
			}
		}
	 
		 
		exports.createJWKStore = createJWKStore;
		exports.getJWKStore = getJWKStore;
		exports.loadKeyStore = loadKeyStore;
		exports.keyStore = keyStore;
		exports.crJWKFromPrivateKeyPEM = crJWKFromPrivateKeyPEM;
		exports.createstdJWKStore = createstdJWKStore;
		exports.x5jwtsjson = x5jwtsjson;
		exports.getJWKPublic = getJWKPublic;
		exports.createJWToken = createJWToken;
		exports.crJWEToken = crJWEToken;
		exports.getDemoUserJWKSets = getDemoUserJWKSets;
		// function call below creates JWKS in JWKSets directory
		// createJWKStore('karan123456', './user_certs/', 'password',
		// '', '', '');
		// function call below creates JWT in user_jwtokens director
		// createJWToken('karan123456', './user_jwks/', '', '', '', '');
		
		// var ret = getJWKStore('', '');
		// var ret = loadKeyStore('./JWKSets/keys.json', '',
		// '').then(console.log("KeyS: " + keyStore));
		//var prvKey = crJWKFromPrivateKeyPEM('yogesh', './demo_certs/', 'yogesh', '', '', '');
		// getJWKPublic('karan123456', './user_jwks/', '', '', '', '');
		// createJWToken('karan123456', './user_certs/', '', '', '',
		// '');
		// var pubk = getCA_P12_PrivateKey('karan123456',
		// './user_certs/'+'karan123456'+'_certp12b64.p12', 'password');
		// console.log("pubkey: " + JSON.stringify(pubk));
		
		// function below encrypts and decrypts a JWT
		// createstdJWKStore('karan123456', './user_certs/',
		// 'password');
		// crJWEToken('karan123456', 'password', './user_certs/', '',
		// '', '', '');
		// x5jwtsjson('karan123456', './user_certs/', 'password');
