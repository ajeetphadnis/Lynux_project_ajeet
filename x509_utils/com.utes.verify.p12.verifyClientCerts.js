/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * 
 */
require('dotenv').config();
var forge = require('node-forge');
var fs = require('fs');
const Users =  require("../models/com.utes.auth.users");


var debug = process.env.DEBUG19;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
}


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
	ocsp: '',
	newuser: {}
};



/**
 * compareDates
 * @param {*} date1 
 * @param {*} date2 
 * @param {*} date3 
 * @returns 
 */
function compareDates(date1, date2, date3) {
    var g1 = date1;
    var g2 = date2;
    var g3 = date3;
    
    if (g1.getTime() < g2.getTime()) {
        console.log("date/time present is lesser than not-before");
        console.log("Certificate date validity not started");
        return 'NOT_BEFORE';
    } else if ((g1.getTime() > g2.getTime()) && (g1.getTime() < g3.getTime())) {
	console.log("date/time present is greater than not-before");
	console.log("date/time present is lesser than not-after");
	console.log("Certificate date validity passed");
	return 'OK';
    } else if ((g1.getTime() > g3.getTime())) {
	console.log("date/time present is greater than not-after");
	console.log("Certificate date validity expired");
	return 'EXPIRED';
    } else {
	console.log("both are equal");
	return 'OK_EQL';
    }
}


/**
 * getP12PrivateKey
 * @param {*} user 
 * @param {*} filePath 
 * @param {*} pass 
 * @returns 
 */
function getP12PrivateKey ( user, filePath, pass ) {
    // Read file in binary contents
    console.log("loadCA_P12Cert001: ");
    var p12 = fs.readFileSync(filePath);
    console.log("loadCA_P12Cert002: "+ filePath +  '  ' + pass);
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
 * getP12Certs
 * @param {*} user 
 * @param {*} filePath 
 * @param {*} pass 
 * @returns 
 */
function getP12Certs(user, filePath, pass) {
    var keyFile = fs.readFileSync(filePath, 'binary');
    var p12Asn1 = forge.asn1.fromDer(keyFile);
    var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass);
    var bags = p12.getBags({bagType: forge.pki.oids.certBag});
    var bag = bags[forge.pki.oids.certBag][0];
    var certStat;
    // convert to ASN.1, then DER, then PEM-encode
    // generate pem from cert
    var certificate = forge.pki.certificateToPem(bag.cert);
	    // var pem_cert = forge.pem.encode(msg);
	    const cert = forge.pki.certificateFromPem(certificate);
	    const caStore = forge.pki.createCaStore([ cert ]);
	    var verify = forge.pki.verifyCertificateChain(caStore, [ cert ], null);
	    if (verify) {
		console.log("CA-Cert verify:  successful  " + verify);
	    } else {
		console.log("CA-Cert verify:  failed  " + verify);
	    }
	    
	    var stat = compareDates(new Date(), cert.validity.notBefore, cert.validity.notAfter);
	    if (stat === 'OK' && verify) {
		certStat = 'GOOD';
	    } else {
		certStat = 'NOT_GOOD';
	    }
	    // return certificate;
	    const prvKey = getP12PrivateKey(user, filePath, pass);
	    hashForge = forge.md.sha1.create();
	    const keyHash = hashForge.update((cert.issuer.getField('CN').value).toString("binary"));
	    const keySh = hashForge.digest().toHex();
	    const orgHash = hashForge.update((cert.issuer.getField('O').value).toString("binary"));
	    const orgSh = hashForge.digest().toHex();
	    const data = {
		    OCSPResponsestatus: cert.subject.getField('CN').value,
		    ResponseType: 'Basic OCSP Response',
		    Version: 1,
		    ResponderID: cert.issuer.getField('CN').value,
		    ProducedAt: new Date(),		    
		    ResponseList_HashAlgorithm: 'SHA1',
		    ResponseList_IssuerNameHash: orgSh,
		    ResponseList_IssuerKeyHash: keySh,
		    ResponseList_CertStatus: certStat,
		    ResponseList_RevocationTime: '',
		    ResponseList_ThisUpdate: new Date(),
		    ResponseList_NextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
		    countryName: cert.issuer.getField('C').value,
		    organizationName: cert.issuer.getField('O').value,
		    serialNumber: cert.serialNumber,
		    notBefore: cert.validity.notBefore,
		    notAfter: cert.validity.notAfter,
		  };
		  // return data;
// const subject = cert.subject.attributes
// .map(attr => [attr.shortName, attr.value].join('='))
// .join(', ');
	    
	    
	    if(debug) {console.log("cert data:  " + JSON.stringify(data));}
	    user.ocsp = JSON.stringify(data);
	    return JSON.stringify(data);
}



/**
 * getDemoUserOCSP
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
async function getDemoUserOCSP(req, res, next) {
	 try{
			if (req.method === 'GET' && req.method !== 'POST') {
				console.log('GET');
				req.on('data', function (chunk) {
			        if(debug) {console.log('getDemoUserOCS:GET DATA!' + JSON.stringify(data));}
			    });
			}				
			if (req.method === 'POST' && req.method !== 'GET') {
				console.log('getDemoUserOCS:POST');
				if(debug) {console.log('getDemoUserOCS: Got body:', req.body);}
				if(req.body.udata) {
					var udat = JSON.parse(JSON.stringify(req.body.udata));
					JSON.parse(udat, (key, value) => {
						  if (typeof value === 'string') {
						    if(debug) {console.log("key:  " + key + "  value:  " + value);}
						    if(key === 'uid') user.uid = value;
						    if(key === 'ope') user.oprf = value;
						    if(key === 'upass') user.pass = value;
						  }
						  //return value;
						  user.serv = user.oprf;
					});
					console.log("getDemoUserOCS001:   called ...." + user.uid);
					user.newuser = new Users();
					user.newuser.nameIdentifier = user.uid;
					user.newuser.password = user.pass;
					user.newuser.commonName = 'utesdemo.com';
					user.newuser.orgName = 'utesdemo.com';
					 //ksVals.CustomerId =  user.uid;
					 uid = user.uid;
					 console.log("getDemoUserOCSP:POST:  " + uid);
					 var ocspVar = getP12Certs (uid, './demo_certs/'+uid+'_certp12b64.p12', user.pass);
					 user.ocsp = JSON.parse(ocspVar);
			 		await res.status(200).send({ user: user});
				}
			}
		} catch (err) {
			console.log(err);
		}
	}




exports.getP12Certs = getP12Certs;
exports.getP12PrivateKey = getP12PrivateKey;
exports.getDemoUserOCSP = getDemoUserOCSP;

//getP12Certs('ajeetphadnis', './user_certs/ajeetphadnis_certp12b64.p12', 'ajeetphadnis');
// getP12PrivateKey('kunalpandya', './user_certs/kunalpandya_certp12b64.p12', 'kunalpandya');
//getP12Certs('yogesh', './demo_certs/yogesh_certp12b64.p12', 'yogesh');