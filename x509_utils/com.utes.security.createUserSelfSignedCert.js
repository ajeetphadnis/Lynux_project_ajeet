/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * https://www.npmjs.com/package/node-forge/v/0.8.3 oid : ns-comment field. Its
 * OID is 2.16.840.1.113730.1.13 http://oidref.com/
 * https://nodejs.org/api/addons.html - for c and c++ your own CA:
 * https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/
 * CA with openssl:-
 * http://cs.uccs.edu/~cs526/studentproj/projS2008/cshort/doc/X509ProjectPaper.pdf
 * 
 * 
 */
require('dotenv').config();
const fs 	= require('fs');
var forge = require('node-forge');
var usrDb = require('../models/com.utes.mongo.crud');
var usrStruct = require('../models/com.utes.mongo.crud');
const Users =  require("../models/com.utes.auth.users");

var debug = process.env.DEBUG18;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
}


var newuser = new Users ({
	  nameIdentifier: '',
	  emailAddress: '',
	  fullname: '',
	  firstname: '',
	  lastname: '',
	  password: '',
	  mobilePhone: '',
	  groups: '',
});

var pki = forge.pki;
var client;

/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns a hexString is considered negative if it's most significant bit is 1
 *          because serial numbers use ones' complement notation this RFC in
 *          section 4.1.2.2 requires serial numbers to be positive
 *          http://www.ietf.org/rfc/rfc5280.txt
 * 
 */
function toPositiveHex(hexString){
  var mostSiginficativeHexAsInt = parseInt(hexString[0], 16);
  if (mostSiginficativeHexAsInt < 8){
      if(debug) {console.log("Random:  " + hexString);}
    return hexString;
  }

  mostSiginficativeHexAsInt -= 8;
  return mostSiginficativeHexAsInt.toString() + hexString.substring(1);
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
function randomSerialNumber () {
    return toPositiveHex(forge.util.bytesToHex(forge.random.getBytesSync(9)))
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
function getHexSerialNr(length) {
    const genRanHex = size => [...Array(size)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
    var hx = genRanHex(length);
    // hx = hx.replace(/..\B/g, '$&:');
    return hx;
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
async function createUserSelfSignedCert(uid, text, data, pass, req, res, next) {
	var password = pass;
	const url = 'mongodb://localhost:27017/auth_users\', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
	client = usrDb.getMongoClient(url);
	await usrDb.getUserStruct(uid, req, res, next).then(res => {
		if (uid != null && uid != '') {
			var data = JSON.stringify(usrStruct);
			JSON.parse(data, (key, value) => {
				  if (typeof value === 'string') {
				    // console.log("key: " + key);
				    if(key === 'nameIdentifier') newuser.nameIdentifier = value;
				    if(key === 'emailAddress') newuser.emailAddress = value;
				    if(key === 'fullname') newuser.fullname = value;
				    if(key === 'commonName') newuser.commonName = value;
				    if(key === 'orgName') newuser.orgName = value;
				    if(key === 'password') newuser.password = value;
				    if(key === 'mobilePhone') newuser.mobilePhone = value;
				    if(key === 'groups') newuser.groups = value;
				  }
				  // return value;
				});
		}});
	if(debug) {console.log("uid001:  " + uid +  "   pass:  " + pass + "   attrs:  " + JSON.stringify(newuser));}
	if (uid && (typeof uid !== 'undefined' && pass !== '')) {
		try {
			// generate a keypair or use one you have already
			var keys = pki.rsa.generateKeyPair(2048);
			var uid = uid;
			// create a new certificate
			// create a certificate
			  if(debug) {console.log('Creating self-signed certificate...   ' + "   commonname:  " + newuser.commonName + "   orgname:  " + newuser.orgName);}
			  var cert = forge.pki.createCertificate();
			  cert.publicKey = keys.publicKey;
			  // cert.serialNumber = '01';
			  // cert.serialNumber = randomSerialNumber ();
			  cert.serialNumber = getHexSerialNr(16);
			  var today = new Date();
			  var nextweek = new Date(today.getFullYear(), today.getMonth(), today.getDate()+7);
			  cert.validity.notBefore = today;
			  cert.validity.notAfter = nextweek;
			  // cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear()
			    // + 1);
			  var attrs_issuer = [
					{
					    name : 'commonName',
					    value : 'com.utes/intermediate_ca-domain'
					},
					{
					    name : 'countryName',
					    value : 'NO'
					},
					{
					    shortName : 'ST',
					    value : 'Oslo-Akerhusa'
					},
					{
					    name : 'localityName',
					    value : 'Oslo'
					},
					{
					    name : 'organizationName',
					    value : 'UTES_INTERMEDIATE_CA_TRUST_DOMAIN Inc'
					},
					{
					    shortName : 'OU',
					    value : 'INTERMEDIATE_CA_TRUST_DOMAIN CryptoApps'
					} ];
			  var attrs = [{
				  name: 'commonName',
				  value: newuser.commonName
				}, {
				  name: 'countryName',
				  value: 'US'
				}, {
				  shortName: 'ST',
				  value: newuser.orgName
				}, {
				  name: 'localityName',
				  value: newuser.orgName
				}, {
				  name: 'organizationName',
				  value: newuser.orgName
				}, {
				  shortName: 'OU',
				  value: newuser.nameIdentifier
				}];
			  cert.setSubject(attrs);
			  cert.setIssuer(attrs_issuer);
			  cert.setExtensions([{
			    name: 'basicConstraints',
			    cA: true
			  }, {
			    name: 'keyUsage',
			    keyCertSign: true,
			    digitalSignature: true,
			    nonRepudiation: true,
			    keyEncipherment: true,
			    dataEncipherment: true
			  }, {
				  name: 'extKeyUsage',
				  serverAuth: true,
				  clientAuth: true,
				  codeSigning: true,
				  emailProtection: true,
				  timeStamping: true
				}, {
				    name: 'nsCertType',
				    client: true,
				    server: true,
				    email: true,
				    objsign: true,
				    sslCA: true,
				    emailCA: true,
				    objCA: true
				}, {
			    name: 'subjectAltName',
			    altNames: [{
			      type: 6, // URI
			      value: 'domain=http://'+newuser.commonName
			    }]}, {
				 name: 'subjectKeyIdentifier'
			    }, {
				name: 'authorityKeyIdentifier',
				value: 'keyid: 20:D6:0E:C6:18:B1:76:C5:E2:65:8F:04:4F:41:78:5D:CA:6B:08:BE'
				// keyid:
				// '20:D6:0E:C6:18:B1:76:C5:E2:65:8F:04:4F:41:78:5D:CA:6B:08:BE',
				// DirName: '/CN=Easy-RSA CA'
			    }, {
				name: 'authorityInfoAccess',
				value: 'https://www.prathamesh-phadnis.com',
// authorityInfoAccessIssuers:
// 'http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt'
			    }, {
				name: 'cRLDistributionPoints',
				value: 'https://www.prathamesh-phadnis.com/domain_user'
			    }, {
				name: 'certificatePolicies',
				value: 'Policy: X509v3 Any Policy'+'\r\n'+
				       '  CPS: https://www.prathamesh-phadnis.com/repository/'
			    }
			    
			  ]);
			  
			  // self-sign certificate
			  // cert.sign(keys.privateKey);
			  // Use the provided CA private key to sign the
			    // certificate.
			    const signer = keys.privateKey;
			    cert.sign(signer, forge.md.sha256.create());
			  console.log('Certificate created.');
		
			  // create PKCS12
			  console.log('\nCreating PKCS#12...');
			  // password = pass;
			  var newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
			    keys.privateKey, [cert], password,
			    {generateLocalKeyId: true, friendlyName: newuser.orgName});
			  var newPkcs12Der = forge.asn1.toDer(newPkcs12Asn1).getBytes();
			  if (uid != null) {
				  fs.writeFile('./user_certs/'+uid+'_certp12b64.p12', newPkcs12Der, {encoding: 'binary'} , function (err, file) {
						if (err) throw err;
						console.log('Saved  certp12b64.p12 file!');
					});
			  }
	
			// generate a p12 that can be imported by
			// Chrome/Firefox/iOS
			// (requires the use of Triple DES instead of AES)
			var p12Asn1 = forge.pkcs12.toPkcs12Asn1(
			  keys.privateKey, [cert], password,
			  {algorithm: '3des'});
			 
			// base64-encode p12
			var p12Der = forge.asn1.toDer(p12Asn1).getBytes();
			var p12b64 = forge.util.encode64(p12Der);
	// fs.writeFile('certp12b64.p12', p12b64, function (err, file) {
	// if (err) throw err;
	// console.log('Saved p12b64.p12 file!');
	// });
			// end p12 new
			
			
			 // console.log('\nBase64-encoded new PKCS#12:');
			 // console.log(forge.util.encode64(newPkcs12Der));
		
			  // create CA store (w/own certificate in this
			    // example)
			  var caStore = forge.pki.createCaStore([cert]);
			  if (uid ) {
				  fs.writeFile('./user_certs/'+uid+'_certP12.p12', forge.util.encode64(newPkcs12Der), function (err, file) {
						if (err) throw err;
						console.log('Saved!');
					});
			  }
			  console.log('\nLoading new PKCS#12 to confirm...');
			  loadPkcs12(uid, newPkcs12Der, pass, caStore);
			} catch(ex) {
			  if(ex.stack) {
			    console.log(ex.stack);
			  } else {
			    console.log('Error', ex);
			  }
			}
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
	function loadPkcs12(uid, pkcs12Der, password, caStore) {
	  var pkcs12Asn1 = forge.asn1.fromDer(pkcs12Der);
	  var pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, false, password);

	  // load keypair and cert chain from safe content(s) and map to key
	    // ID
	  var map = {};
	  for(var sci = 0; sci < pkcs12.safeContents.length; ++sci) {
	    var safeContents = pkcs12.safeContents[sci];
	    console.log('safeContents ' + (sci + 1));

	    for(var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
	      var safeBag = safeContents.safeBags[sbi];
	      console.log('safeBag.type: ' + safeBag.type);

	      var localKeyId = null;
	      if(safeBag.attributes.localKeyId) {
	        localKeyId = forge.util.bytesToHex(
	          safeBag.attributes.localKeyId[0]);
	        if(debug) {console.log('localKeyId: ' + localKeyId);}
	        if(!(localKeyId in map)) {
	          map[localKeyId] = {
	            privateKey: null,
	            certChain: []
	          };
	        }
	      } else {
	        // no local key ID, skip bag
	        continue;
	      }

	      // this bag has a private key
	      if(safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
	        console.log('found private key');
	        map[localKeyId].privateKey = safeBag.key;
	      } else if(safeBag.type === forge.pki.oids.certBag) {
	        // this bag has a certificate
	        console.log('found certificate');
	        map[localKeyId].certChain.push(safeBag.cert);
	      }
	    }
	  }

	  console.log('\nPKCS#12 Info:');

	  for(var localKeyId in map) {
	    var entry = map[localKeyId];
	    if(debug) {console.log('\nLocal Key ID: ' + localKeyId);}
	    if(entry.privateKey) {
	      var privateKeyP12Pem = forge.pki.privateKeyToPem(entry.privateKey);
	      var encryptedPrivateKeyP12Pem = forge.pki.encryptRsaPrivateKey(
	        entry.privateKey, password);

	      console.log('\nPrivate Key:');
		  // store privatekey
	      if (uid != null) {
			  fs.writeFile('./user_certs/'+uid+'_prvKey.pem', privateKeyP12Pem, {encoding: 'binary'} , function (err, file) {
					if (err) throw err;
					console.log('Saved  user private key file!');
				});
	      }

	      if(debug) {console.log(privateKeyP12Pem);}
	      if(debug) {console.log('Encrypted Private Key password: ' + password );}
	      if(debug) {console.log(encryptedPrivateKeyP12Pem);}
	    } else {
	      console.log('');
	    }
	    if(entry.certChain.length > 0) {
	      console.log('Certificate chain:');
	      var certChain = entry.certChain;
	      for(var i = 0; i < certChain.length; ++i) {
	        var certP12Pem = forge.pki.certificateToPem(certChain[i]);        
	        if(debug) {console.log(certP12Pem);}
	      }
	      fs.writeFile('./user_certs/'+uid+'_selfsigned.crt', certP12Pem, function (err, file) {
	    		if (err) throw err;
	    		console.log('Saved!');
	    	});
	    }
	  }
	}

exports.createUserSelfSignedCert = createUserSelfSignedCert;
//createUserSelfSignedCert('kunalpandya', './user_certs/kunalpandya_certp12b64.p12', '', 'kunalpandya', '', '', '');