// http://www.guyrutenberg.com/2013/12/28/creating-self-signed-ecdsa-ssl-certificate-using-openssl/
//const child_process = require('child_process');
const fs = require ('fs');
const { exec } = require('child_process');


//openssl('openssl req -config csr.cnf -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout key.key -out certificate.crt')
var osl_home = process.env.OPENSSL_HOME;
var osl_conf = process.env.OPENSSL_CONF;
//openssl('openssl req -config csr.cnf -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout key.key -out certificate.crt');
/*execFile(__dirname + '/processNodejsImage.sh', (error, stdout, stderr) => {
    if (error) {
      console.error(`error: ${error.message}`);
      return;
    }*/

    /*
    exec('dir', (error, stdout, stderr) => {
        if (error) {
          console.error(`error: ${error.message}`);
          return;
        }
      
        if (stderr) {
          console.error(`stderr: ${stderr}`);
          return;
        }
      
        console.log(`stdout:\n${stdout}`, 'utf8');
      });*/
function createEcDsaPrivateKey(algo, path) {
    console.log("openssl_home:   "+ osl_home +  "       osl_conf:    " + osl_conf);
    exec('openssl ecparam -name secp521r1 -genkey -param_enc explicit -out jwks/ecdsa_certs/private-aj-key.pem', function (err, buffer) {
        console.log(err, buffer.toString());
    });
  }

    
const password = "123";

/*exec(
    'openssl rsa -in key-aj-enc.pem -passin pass:${password}',
    (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            return;
        }
        console.log(`stdout: ${stdout}`);
        console.error(`stderr: ${stderr}`);
    }
);*/
//https://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-the-command-line
//https://ouestcode.com/journal/archive/2014-generate-self-signed-ssl-certificate-without-prompt-noninteractive-mode
//https://github.com/acmesh-official/acme.sh/issues/597
// How to add private key to certificate: https://gist.github.com/marta-krzyk-dev/83168c9a8e985e5b3b1b14a98b533b9c
async function createEcDsaCert(user, dnStr, validityTime, pkeyStr) {
    var keyfil = user+'.pem';
    var servfil = 'jwks/ecdsa_certs/srv_'+keyfil;
    var keypath = 'jwks/ecdsa_certs/'+keyfil;
    var ppkey = await pkey.crAns1Eckeys(keyfil, 'prime256v1', 'jwks/ecdsa_certs/', 'private');  // 1. prime256v1, 2. secp256k1
    var dn = "//C=NO\ST=Akershus\L=Oslo\O=UTES.Com\OU=UTES-Protocols\CN=utes.com\emailAddress=ap@phadnis.no";
    var c="NO";
    var st="Akershus";
    var l="Oslo";
    var o="UTES.Com";
    var ou="UTES-Protocols";
    var cn="utes.com";
    var emailAdd="ap@phadnis.no";
    console.log("vars:  " + c + "   " + cn);

    //exec(`openssl req -new -x509 -key jwks/ecdsa_certs/private-aj-key.pem -subj /CN=${cn}/C=${c}/O=${o}/ST=${st}/L=${l}/OU=${ou}/emailAddress=${emailAdd} -addext  "subjectAltName=DNS:utes.phadnis.com"  -addext "certificatePolicies = 1.2.3.4" \ -out jwks/ecdsa_certs/aj_ec_server.pem -days 730`, function (err, buffer) {
      exec(`openssl req -new -x509 -key ${keypath} -subj /CN=${cn}/C=${c}/O=${o}/ST=${st}/L=${l}/OU=${ou}/emailAddress=${emailAdd} -addext  "subjectAltName=DNS:utes.phadnis.com"  -addext "certificatePolicies = 1.2.3.4" \ -out ${servfil} -days 730`, function (err, buffer) {  
      console.log(err, buffer.toString());
    });
}




//const child_process = require('child_process');
// link for below solution: https://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-the-command-line
// link: https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs
// for interactive 

/*const openssl = child_process.spawn('openssl', [
  'req', '-new', '-x509',
  '-key',
  "private-aj-key.pem", 
], { stdio: "inherit" });*/

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

//createEcDsaPrivateKey('', '');
createEcDsaCert('ajeet', '', '', '');