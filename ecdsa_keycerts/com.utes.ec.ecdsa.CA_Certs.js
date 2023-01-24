/*
# ECDSA 
#   https://www.youtube.com/watch?v=LIlyb_rRnPY
## Create CA Certificate
List and select a curve (prime256v1 is a good option).
```
openssl ecparam -list_curves | less
```
Generate a private key for the CA.
```
openssl ecparam -genkey -name prime256v1 -out ca.key
```
Generate a self-signed certificate. 
* `-x509` outputs self-signed certificate instead of a certificate signing request 
* `-nodes` says not to encrypt to private key, if applicable.
```
openssl req -x509 -new -sha256 -nodes -key ca.key -days 3650 -out ca.crt -subj "/C=US/ST=AZ/L=Tempe/O=SW/CN=ca.demo"
```

## Create and Sign Host Certificate
Generate a private key for a host.
```
openssl ecparam -genkey -name prime256v1 -out host.key
```
Use the private key to create a certificate signing request (CSR). We omit `-x509` because we want a CSR, not a self-signed certificate.
```
openssl req -new -sha256 -key host.key -nodes -out host.csr -subj "/C=US/ST=AZ/L=Tempe/O=SW/CN=host.demo"
```
Use the CA to create a signed certificate for this CSR.
```
openssl x509 -req -sha256 -days 730 -in host.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out host.crt
```
(Optionally) convert the host's private key to PKCS#8, which some servers may require.
```
 openssl pkcs8 -topk8 -in host.key -out host-pkcs8.key -nocrypt 
```
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
//     var dn = "//C=NO\ST=Akershus\L=Oslo\O=UTES.Com\OU=UTES-CA\CN=utes.com\emailAddress=ap@phadnis.no";
// ejs data to be sent
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

// CA Credentials
var c="NO";
var st="Akershus";
var l="Oslo";
var o="UTES.Com";
var ou="UTES-CA";
var cn="utes.com";
var emailAdd="ap@phadnis.no";
var pass = 'caroot';

// client / domain Credentials
var cl="";
var stl="";
var ll="";
var ol="";
var oul="";
var cnl="";
var emailAddl="";
var passl = '';


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
   * 
   * @param {*} path 
   * @param {*} timeout 
   * @returns 
   */
  async function checkFileExist(path, timeout = 2000) {
    let totalTime = 0; 
    let checkTime = timeout / 10;
    return await new Promise((resolve, reject) => {
        const timer = setInterval(function() {
            totalTime += checkTime;    
            let fileExists = fs.existsSync(path);    
            if (fileExists || totalTime >= timeout) {
                clearInterval(timer);                
                resolve(fileExists);                
            }
        }, checkTime);
    });
  }

  


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
async function createEcDsaCACert(user, curvType, keyType, validityTime, pkeyStr) {
    var keyfil = user+'.pem';
    var servfil = 'ecdsaKeyCerts/'+user+'_srv.cer';
    var keypath = 'ecdsaKeyCerts/'+user+'_key.pem';
    var ppkey = await crAsn1Eckeys(user, curvType, 'ecdsaKeyCerts/', keyType);  // 1. prime256v1, 2. secp256k1
    var dn = "//C=NO\ST=Akershus\L=Oslo\O=UTES.Com\OU=UTES-CA\CN=utes.com\emailAddress=ap@phadnis.no";
    //console.log("vars:  " + c + "   " + cn);

    //exec(`openssl req -new -x509 -key jwks/ecdsa_certs/private-aj-key.pem -subj /CN=${cn}/C=${c}/O=${o}/ST=${st}/L=${l}/OU=${ou}/emailAddress=${emailAdd} -addext  "subjectAltName=DNS:utes.phadnis.com"  -addext "certificatePolicies = 1.2.3.4" \ -out jwks/ecdsa_certs/aj_ec_server.pem -days 730`, function (err, buffer) {
    //  openssl req -x509 -new -sha256 -nodes -key ca.key -days 3650 -out ca.crt
      await exec(`openssl req -x509 -new -sha256 -nodes -key ${keypath} -subj /CN=${cn}/C=${c}/O=${o}/ST=${st}/L=${l}/OU=${ou}/emailAddress=${emailAdd} -addext  "subjectAltName=DNS:utes.phadnis.com"  -addext "certificatePolicies = 1.2.3.4" \ -out ${servfil} -days 730`, function (err, buffer) {  
      console.log(err, buffer.toString());
    });
    await showECDSACert(user, servfil );
}


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
 async function createEcDsaClientCert(user, curvType, keyType, validityTime, pkeyStr) {
  var keyfil = user+'.pem';
  var csrfil = 'ecdsaKeyCerts/'+user+'_host.csr';
  var keypath = 'ecdsaKeyCerts/'+user+'_hostkey.pem';
  var ppkey = await crAsn1Eckeys(user, curvType, 'ecdsaKeyCerts/', keyType);  // 1. prime256v1, 2. secp256k1
  var dn = "//C=NO\ST=Akershus\L=Oslo\O=UTES.Com\OU=UTES-CA\CN=utes.com\emailAddress=ap@phadnis.no";
  //console.log("vars:  " + c + "   " + cn);

  //exec(`openssl req -new -x509 -key jwks/ecdsa_certs/private-aj-key.pem -subj /CN=${cn}/C=${c}/O=${o}/ST=${st}/L=${l}/OU=${ou}/emailAddress=${emailAdd} -addext  "subjectAltName=DNS:utes.phadnis.com"  -addext "certificatePolicies = 1.2.3.4" \ -out jwks/ecdsa_certs/aj_ec_server.pem -days 730`, function (err, buffer) {
  //  openssl req -x509 -new -sha256 -nodes -key ca.key -days 3650 -out ca.crt
  // openssl req -new -sha256 -key host.key -nodes -out host.csr
    await exec(`openssl req -new -sha256 -key ${keypath} -subj /CN=${cnl}/C=${cl}/O=${ol}/ST=${stl}/L=${ll}/OU=${oul}/emailAddress=${emailAddl} -addext  "subjectAltName=DNS:utes.clients.com"  -addext "certificatePolicies = 1.2.3.4" \ -out ${csrfil} -days 730`, function (err, buffer) {  
    console.log(err, buffer.toString());
  });
  await showECDSAClientCert(user, csrfil );

}


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
 async function createEcDsaCASignedClientCert(user, curvType, keyType, validityTime, pkeyStr) {
  var keyfil = user+'.pem';
  var csrfil = 'ecdsaKeyCerts/'+user+'_host.csr';
  var caCert = 'ecdsaKeyCerts/CA_ROOT_srv.cer';
  var caKey  = 'ecdsaKeyCerts/CA_ROOT_key.pem';
  var clientSignedCert = 'ecdsaKeyCerts/' + user + '_host.cer';
  var keypath = 'ecdsaKeyCerts/'+user+'_hostkey.pem';
  await createEcDsaClientCert(user, curvType, keyType, validityTime, pkeyStr);
  // openssl x509 -req -sha256 -days 730 -in host.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out host.crt
    await exec(`openssl x509 -req -sha256 -days 730 -in ${csrfil} -CA ${caCert} -CAkey ${caKey} -CAcreateserial -out ${clientSignedCert} -days 730`, function (err, buffer) {  
    console.log(err, buffer.toString());
  });
  await checkFileExist(clientSignedCert);
  await showECDSACert(user, clientSignedCert );
  await crEcdsaP12(keypath, clientSignedCert, user);
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
           fs.writeFileSync((path+'/'+user+'_hostkey.pem'), pemKey, 'utf8');
           console.log("privatekey:  " + pemKey);
           return pemKey;
         } else if (type === 'Private' && curvType === 'secp256k1') {
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
          fs.writeFileSync((path+'/'+user+'_hostkey.pem'), pemKey, 'utf8');
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
    var servfil = 'ecdsaKeyCerts/'+user+'_srv.cer';
    var txtfil = 'ecdsaKeyCerts/'+user+'_srv.txt';
    //await exec(`openssl req -out ${txtfil} -text -in ${certFil} `, function (err, buffer) {
    await checkFileExist(certFil); 
    await exec(`openssl x509 -in ${certFil} -text -out ${txtfil} `, async function (err, buffer) {  
      console.log(err, buffer.toString());
  });
}

/**
 * Function: showECDSACert
 * This function  converts the ecDSACertificate into a text format that is
 * human readable. And is used to show in the app's dashboard.
 * @param {*} user 
 * @param {*} certFil 
 */
 async function showECDSAClientCert(user, certFil ) {
  var servfil = 'ecdsaKeyCerts/'+user+'_host.csr';
  var servfilpem = 'ecdsaKeyCerts/'+user+'_host.cer';
  var txtfil = 'ecdsaKeyCerts/'+user+'_csr.txt';
  await checkFileExist(certFil);
  await exec(`openssl req -out ${txtfil} -text -in ${certFil} `, async function (err, buffer) {  
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
        //var servfil = 'ecdsa_keycerts/ecdsaKeyCerts/srv_'+keyfil;
        //var keypath = 'ecdsa_keycerts/ecdsaKeyCerts/'+keyfil;
        var pfxpath = 'ecdsaKeyCerts/'+user+'_srv.p12';
        
        exec(`openssl pkcs12 -export -inkey  ${pkeyfil}  -in ${certfil} -passout pass:${user} -out ${pfxpath} `, function (err, buffer) {  
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
                            cnl = newuser.nameIdentifier.replace(/\s/g, ".");
                            emailAddl = newuser.emailAddress.replace(/\s/g, ".");
                            oul = newuser.fullname.replace(/\s/g, ".");
                            ol = newuser.commonName.replace(/\s/g, ".");
                            stl = newuser.orgName.replace(/\s/g, ".");
                            passl = newuser.password.replace(/\s/g, ".");
                            cl = 'na';
                            ll = 'na';
                        console.log("getEcDsaKeysCerts: POST:   " + cnl);
                        await createEcDsaCASignedClientCert(cnl, curvType, keyType, 356, '');
                        //await createEcDsaCert(cnl, curvType, keyType, '', '');
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

//exports.createEcDsaPrivateKey = createEcDsaPrivateKey;
exports.createEcDsaCACert = createEcDsaCACert;
exports.crAsn1Eckeys = crAsn1Eckeys;
exports.crEcdsaPfx = crEcdsaPfx;
exports.crEcdsaP12 = crEcdsaP12;
exports.crEcdsaP7B = crEcdsaP7B;
exports.getEcDsaKeysCerts = getEcDsaKeysCerts;
exports.createEcDsaClientCert = createEcDsaClientCert;
exports.createEcDsaCASignedClientCert = createEcDsaCASignedClientCert;
//createEcDsaPrivateKey('', '');
//createEcDsaCert('ajeet', '', '', '');
//crEcdsaP7B('', '', 'ajeet');
//crAsn1Eckeys('amar', 'prime256v1', 'ecdsaKeyCerts/', 'Private');
//createEcDsaCACert('CA_ROOT', 'prime256v1', 'Private', 356, '');
//createEcDsaClientCert('Doub-Host', 'prime256v1', 'Private', 356, '');
//createEcDsaCASignedClientCert('PHADNIS-Host', 'prime256v1', 'Private', 356, '');