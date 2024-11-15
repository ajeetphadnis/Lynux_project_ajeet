/* http://www.guyrutenberg.com/2013/12/28/creating-self-signed-ecdsa-ssl-certificate-using-openssl/
 *const child_process = require('child_process');
 *
 * Based on : https://asecuritysite.com/encryption/js_ecdh
 * Node.js has an in-built crypto module and which can be used 
 * to run code using Javascript. This example implements the 
 * Elliptic Curve Diffie Hellman (ECDH) key exchange method.
 * x509 does not recommend brainpool algs from TLS 1.3
 * And hence this implementation is omitting brainpool algs.
 * Benifits of Elliptic curve algs: https://www.digicert.com/faq/ecc.htm
 * To run : node sample_node/com.utes.ec.x509.sect571r1 Type:    secp128r2, brainpoolP512r1 or any other alg
 * https://stackoverflow.com/questions/51046309/crypto-how-to-generate-ecdh-pem
 * https://www.instructables.com/Understanding-how-ECDSA-protects-your-data/
 * https://github.com/indutny/elliptic/
 * https://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-the-command-line
 * https://ouestcode.com/journal/archive/2014-generate-self-signed-ssl-certificate-without-prompt-noninteractive-mode
 * https://github.com/acmesh-official/acme.sh/issues/597
 * How to add private key to certificate: https://gist.github.com/marta-krzyk-dev/83168c9a8e985e5b3b1b14a98b533b9c
 * const child_process = require('child_process');
 * link for below solution: https://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-the-command-line
 * link: https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs
 * Link: https://www.derpturkey.com/inherent-malleability-of-ecdsa-signatures/#:~:text=In%20ECDSA%2C%20inherent%20signature%20malleability,the%20signature%20remains%20perfectly%20valid!
 */
 require('dotenv').config();
var fs = require("fs");
var crypto = require("crypto");
const { generateKeyPair } = require('crypto');
const { exec } = require('child_process');
var BN = require('bn.js');
var asn1 = require('asn1.js');
const path = require('path');
const bodyParser = require('body-parser');
const Users = require("../models/com.utes.auth.users");
var usrDb = require('../models/com.utes.mongo.crud');
var usrStruct = require('../models/com.utes.mongo.crud');

var pubkey;
var prvkey;
var pemKey;


var osl_home = process.env.OPENSSL_HOME;
var osl_conf = process.env.OPENSSL_CONF;
var debug = process.env.DEBUG15;
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

var user = {
  uid: '',
  pass: '',
  serv: '',
  srctxt: '',
  destxt: '',
  jwksets: '',
  oprf: '',
  oprt: '',
  Timestamp: '',
  target: '',
  filetype: '',
  Content: '',
  secenv: '',
  keyInfo: '',
  newuser: {}
};

var c="";
var st="";
var l="";
var o="";
var ou="";
var cn="";
var emailAdd="";
var pass = '';

/**
 * Function: createEcDsaPrivateKey
 * This method calls openssl function to create ecdsa keys
 * @param {*} algo 
 * @param {*} path 
 */
function createEcDsaPrivateKey(algo, path) {
    console.log("openssl_home:   "+ osl_home +  "       osl_conf:    " + osl_conf);
    exec('openssl ecparam -name secp521r1 -genkey -param_enc explicit -out jwks/ecdsa_certs/private-aj-key.pem', function (err, buffer) {
        console.log(err, buffer.toString());
    });
  }


/**
 * Function: toOIDArray
 * This method creates an array of OID elements
 * @param {*} oid 
 * @returns 
 */
function toOIDArray(oid) {
    return oid.split('.').map(function(s) {
      return parseInt(s, 10)
    });
  }

  /**
	 * connMongo: 
	 * @param req
	 * @param res
	 * @returns
	 */
	function connMongo(req, res) {
		// Connection URL
		  const url = 'mongodb://localhost:27017/auth_users\', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
		  usrDb.getMongoClient(url);		
	};


/**
 * Function: createEcDsaCert:
 * This funcation creates ecdsa certificate that can be used for SSL, TLS3
 * digital signing, data encryption and so on.
 * @param {*} user 
 * @param {*} curvType 
 * @param {*} keyType 
 * @param {*} validityTime 
 * @param {*} pkeyStr 
 */
async function createEcDsaCert(user, curvType, keyType, validityTime, pkeyStr) {
    var keyfil = user+'.pem';
    var servfil = 'ecdsa_keycerts/ecdsaKeyCerts/'+user+'_srv.cer';
    var keypath = 'ecdsa_keycerts/ecdsaKeyCerts/'+user+'_key.pem';
    var ppkey = await crAsn1Eckeys(user, curvType, 'ecdsa_keycerts/ecdsaKeyCerts/', keyType);  // 1. prime256v1, 2. secp256k1
    var dn = "//C=NO\ST=Akershus\L=Oslo\O=UTES.Com\OU=UTES-Protocols\CN=utes.com\emailAddress=ap@phadnis.no";
    console.log("vars:  " + c + "   " + cn);

    //exec(`openssl req -new -x509 -key jwks/ecdsa_certs/private-aj-key.pem -subj /CN=${cn}/C=${c}/O=${o}/ST=${st}/L=${l}/OU=${ou}/emailAddress=${emailAdd} -addext  "subjectAltName=DNS:utes.phadnis.com"  -addext "certificatePolicies = 1.2.3.4" \ -out jwks/ecdsa_certs/aj_ec_server.pem -days 730`, function (err, buffer) {
      exec(`openssl req -new -x509 -key ${keypath} -subj /CN=${cn}/C=${c}/O=${o}/ST=${st}/L=${l}/OU=${ou}/emailAddress=${emailAdd} -addext  "subjectAltName=DNS:utes.phadnis.com"  -addext "certificatePolicies = 1.2.3.4" \ -out ${servfil} -days 730`, function (err, buffer) {  
      console.log(err, buffer.toString());
    });
    await showECDSACert(user, servfil );
}


/**
 * Function: crAsn1EcKeys
 * This method creates ASn1 formated ecdsa keys for prime256v1 curve type.
 * @param {*} user 
 * @param {*} curvType 
 * @param {*} path 
 * @param {*} type 
 * @returns 
 */
async function crAsn1Eckeys(user, curvType, path, type) {
    // Define ECPrivateKey from RFC 5915
       var ECPrivateKey = asn1.define('ECPrivateKey', function() {
         this.seq().obj(
           this.key('version').int(),
           this.key('privateKey').octstr(),
           this.key('parameters').explicit(0).objid().optional(),
           this.key('publicKey').explicit(1).bitstr().optional()
         );
       });
   
       // Generate the DH keys
       // var ecdh = crypto.createECDH('brainpoolP512t1');
       if (type === 'Private' && curvType === 'prime256v1') {
           var ecdh = crypto.createECDH(curvType);
           ecdh.generateKeys();
           // Generate the PEM-encoded private key
           pemKey = ECPrivateKey.encode({
             version: new BN(1),
             privateKey: ecdh.getPrivateKey(),
             // OID for brainpoolP512t1
             // parameters: toOIDArray('1.3.36.3.3.2.8.1.1.14')
             parameters: toOIDArray('1.2.840.10045.3.1.7')
           }, 'pem', { label: 'EC PRIVATE KEY' });
           fs.writeFileSync((path+'/'+user+'_key.pem'), pemKey, 'utf8');
           console.log("privatekey:  " + pemKey);
           return pemKey;
         }
       // Sign data
   //    var sign = crypto.createSign('sha512');
   //    sign.update('Test this data for verify method');
   //    var signature = sign.sign(pemKey, 'hex');
   //
   //    console.log('signature', signature);
   }



/**
 * Function: showECDSACert
 * This function  converts the ecDSACertificate into a text format that is
 * human readable. And is used to show in the app's dashboard.
 * @param {*} user 
 * @param {*} certFil 
 */
async function showECDSACert(user, certFil ) {
    var servfil = 'ecdsa_keycerts/ecdsaKeyCerts/'+user+'_srv.cer';
    var txtfil = 'ecdsa_keycerts/ecdsaKeyCerts/'+user+'_srv.txt';
    exec(`openssl x509 -in ${servfil} -text -out ${txtfil} `, function (err, buffer) {  
      console.log(err, buffer.toString());
  });
}



/**
 * Function: crEcdsaPfx
 * This function takes the private key and certificate and formats it to pfx format
 * The pfx format is than used by clients.
 * @param {*} pkeyfil 
 * @param {*} certfil 
 * @param {*} user 
 */
   async function crEcdsaPfx(pkeyfil, certfil, user) {
        var keyfil = user+'.pem';
        var servfil = 'ecdsa_keycerts/ecdsaKeyCerts/srv_'+keyfil;
        var keypath = 'ecdsa_keycerts/ecdsaKeyCerts/'+keyfil;
        var pfxpath = 'ecdsa_keycerts/ecdsaKeyCerts/srv_'+user+'.pfx';
        
        exec(`openssl pkcs12 -export -inkey  ${keypath}  -in ${servfil} -passout pass:${user} -out ${pfxpath} `, function (err, buffer) {  
            console.log(err, buffer.toString());
        });
    }


    /**
     * Function: crEcdsaP12
     * This function takes the private key and certificate and formats it to p12 format
     * The p12 format is than used by clients.
     * @param {*} pkeyfil 
     * @param {*} certfil 
     * @param {*} user 
     */
    async function crEcdsaP12(pkeyfil, certfil, user) {
        var keyfil = user+'.pem';
        var servfil = 'ecdsa_keycerts/ecdsaKeyCerts//srv_'+keyfil;
        var keypath = 'ecdsa_keycerts/ecdsaKeyCerts/'+keyfil;
        var pfxpath = 'ecdsa_keycerts/ecdsaKeyCerts/srv_'+user+'.p12';
        
        exec(`openssl pkcs12 -export -inkey  ${keypath}  -in ${servfil} -passout pass:${user} -out ${pfxpath} `, function (err, buffer) {  
            console.log(err, buffer.toString());
        });
    }


     /**
     * Function: crEcdsaP12
     * This function takes the private key and certificate and formats it to P7B format
     * The P7B format is than used by clients.
     * @param {*} pkeyfil 
     * @param {*} certfil 
     * @param {*} user 
     */
    async function crEcdsaP7B(pkeyfil, certfil, user) {
        var keyfil = user+'.pem';
        var servfil = 'ecdsa_keycerts/ecdsaKeyCerts//srv_'+keyfil;
        var keypath = 'ecdsa_keycerts/ecdsaKeyCerts/'+keyfil;
        var pfxpath = 'ecdsa_keycerts/ecdsaKeyCerts/srv_'+user+'.p7b';
        
        exec(`openssl pkcs12 -export -inkey  ${keypath}  -in ${servfil} -passout pass:${user} -out ${pfxpath} `, function (err, buffer) {  
            console.log(err, buffer.toString());
        });
    }
   


    /**
     * Function: getEcDsaKeysCerts
     * This function is the inter face to ejs to visualize the certificate.
     * @param {*} req 
     * @param {*} res 
     * @param {*} next 
     */
    async function getEcDsaKeysCerts(req, res, next) {
      req.app.set("../views", path.join(__dirname));
			req.app.set("view engine", "ejs");
      var txtfil = 'ecdsa_keycerts/ecdsaKeyCerts/';
			//const { check, validationResult } = require('express-validator');
			var urlencodedParser = bodyParser.urlencoded({ extended: true });
			// get AJAX sent data
			if (req.method === 'GET' && req.method !== 'POST') {
                console.log('getEcDsaKeysCerts:   GET');
                req.on('data', function (chunk) {
                    if(debug) {console.log('GET DATA!' + JSON.stringify(data));}
                });			
			}
			
			if (req.method === 'POST' && req.method !== 'GET') {
        // parse application/x-www-form-urlencoded
        req.app.use(bodyParser.urlencoded({ extended: false }));
        // parse application/json
        req.app.use(bodyParser.json());
				console.log('getEcDsaKeysCerts: POST');
            var dat = JSON.stringify(req.body.udata);
            console.log('getEcDsaKeysCerts: POST2:    ' + dat);
            try {
              if (typeof dat !== 'undefined' && dat !== null && dat !== '') {
                  dat = dat.replace(/\\/g, '');
                  dat = dat.slice(1, -1);
                  console.log('getEcDsaKeysCerts: POST3:  ' + dat);
                  var uid = '';
                  var curvType = '';
                  var keyType = '';
                  var pas = '';
                  JSON.parse(dat, (key, value) => {
                      if (typeof value === 'string') {
                        if(key === 'uid') uid = value;
                        if(key === 'ope') curvType = value;
                        if(key === 'key') keyType = value;
                        if(key === 'upass') pas = value;
                      }
                      console.log("vals:  " + uid + '   ' + keyType + '   ' + pas);
                    });
                  //}
                    if (uid) {
                        txtfil = txtfil+uid+'_srv.txt';
                        connMongo(req, res);
                        await usrDb.getUserStruct(uid, req, res, next).then(res => {
                            if (uid != null && uid != '') {
                                var data = JSON.stringify(usrStruct);
                                JSON.parse(data, (key, value) => {
                                      if (typeof value === 'string') {
                                        //console.log("key:  " + key);
                                        if(key === 'nameIdentifier') newuser.nameIdentifier = value;
                                        //if(key === 'nameIdentifier') cn = value;
                                        if(key === 'emailAddress') newuser.emailAddress = value;
                                        //if(key === 'emailAddress') emailAdd = value;
                                        if(key === 'fullname') newuser.fullname = value;
                                        //if(key === 'fullname') ou = value;
                                        if(key === 'commonName') newuser.commonName = value;
                                        //if(key === 'commonName') o = value;
                                        if(key === 'orgName') newuser.orgName = value;
                                        //if(key === 'orgName') st = value;
                                        if(key === 'password') newuser.password = value;
                                        //if(key === 'mobilePhone') newuser.mobilePhone = value;
                                        if(key === 'groups') newuser.groups = value;
                                      }
                                      //return value;
                                    });
                                };
                            });
                            cn = newuser.nameIdentifier.replace(/\s/g, ".");
                            emailAdd = newuser.emailAddress.replace(/\s/g, ".");
                            ou = newuser.fullname.replace(/\s/g, ".");
                            o = newuser.commonName.replace(/\s/g, ".");
                            st = newuser.orgName.replace(/\s/g, ".");
                            pass = newuser.password.replace(/\s/g, ".");
                            c = 'na';
                            l = 'na';
                        console.log("getEcDsaKeysCerts: POST:   " + cn);
                        await createEcDsaCert(cn, curvType, keyType, '', '');
                        req.app.session = req.session;
                        req.app.session.uid = req.body.uid;
                        req.app.session.upw = req.body.uid;
                        //await res.status(200).send({ user: user});
                        var ecdsaCert = fs.readFileSync(txtfil, 'utf-8');
                        console.log("ECDSA Cert Text:   " + ecdsaCert);
                        user.srctxt = ecdsaCert;
                        randusr = user;
                        await res.status(200).send({ user});
                  }
              } /*else {
                //await res.status(200).send({ user});
                randusr = JSON.stringify(user);
                res.render('demo_user', {randusr: randusr, user: user});
              }*/
            } catch (err) {
              console.log(err);
            }
        }
    }


// for non-interactive
//DN parameters:
/*Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:New York
Locality Name (eg, city) []:Brooklyn
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Example Brooklyn Company
Organizational Unit Name (eg, section) []:Technology Division
Common Name (e.g. server FQDN or YOUR name) []:examplebrooklyn.com
Email Address []:
Issuer: C = AU, ST = stateA, L = cityA, O = companyA, OU = sectionA, CN = domain, emailAddress = email@email.com

-Country US \
-State "New Sweden" \
-Locality Stockholm \
-Organization "Scandanavian Ventures, Inc." \
-CommonName  foobar.com \
-EmailAddress gustav@foobar.com \
-Company FooBar


var dn = "/C=NO/ST=Akershus/L=Oslo/O=UTES.Com/OU=UTES-Protocols/CN=utes.com/emailAddress=ap@phadnis.no";
const openssl = child_process.exec('openssl', [
  'req', '-new', '-x509',
  '-key', "private-aj-key.pem", 
  '-subj', "/C=NO/ST=Akershus/L=Oslo/O=UTES.Com/OU=UTES-Protocols/CN=utes.com/emailAddress=ap@phadnis.no",
  /*'-Country', "NO",
  '-Locality', "Akershus",
  '-Organization', "UTES.Com",
  '-CommonName', "utes.com",
  '-EmailAddress', "ap@phadnis.no", 
  '-out', "jwks/ecdsa_certs/utes_ecdsa_crt",
]);*/

exports.createEcDsaPrivateKey = createEcDsaPrivateKey;
exports.createEcDsaCert = createEcDsaCert;
exports.crAsn1Eckeys = crAsn1Eckeys;
exports.crEcdsaPfx = crEcdsaPfx;
exports.crEcdsaP12 = crEcdsaP12;
exports.crEcdsaP7B = crEcdsaP7B;
exports.getEcDsaKeysCerts = getEcDsaKeysCerts;

//createEcDsaPrivateKey('', '');
//createEcDsaCert('ajeet', '', '', '');
//crEcdsaP7B('', '', 'ajeet');