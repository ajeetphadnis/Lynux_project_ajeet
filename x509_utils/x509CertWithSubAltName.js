/**
 * Module: 
 * import libraries
 */ import libraries
const forge = require('node-forge');
const crypto = require('crypto');
const fs = require('fs');
const pki = forge.pki;


/**
 * Function: genX509CertWithSubjAltName
 */
async function genX509CertWithSubjAltName() {
    // generate a keypair and create an X.509v3 certificate
    var keys = pki.rsa.generateKeyPair(2048);
    var cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;

    // NOTE: serialNumber is the hex encoded value of an ASN.1 INTEGER.
    // Conforming CAs should ensure serialNumber is:
    // - no more than 20 octets
    // - non-negative (prefix a '00' if your value starts with a '1' bit)
    cert.serialNumber = '01' + crypto.randomBytes(19).toString("hex"); // 1 octet = 8 bits = 1 byte = 2 hex chars
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1); // adding 1 year of validity from now
    var attrs = [{
        name: 'commonName',
        value: 'example.org'
    }, {
        name: 'countryName',
        value: 'US'
    }, {
        shortName: 'ST',
        value: 'Texas'
    }, {
        name: 'localityName',
        value: 'Austin'
    }, {
        name: 'organizationName',
        value: 'Texas Toast Coffee Shop'
    }, {
        shortName: 'OU',
        value: 'Test'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
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
            value: 'http://texas-toast.coffee/shop'
        }, {
            type: 7, // IP
            ip: '127.0.0.1'
        }]
    }, {
        name: 'subjectKeyIdentifier'
    }]);

    // self-sign certificate
    cert.sign(keys.privateKey);

    // convert a Forge certificate to PEM
    var pem = pki.certificateToPem(cert);

    console.log();
    console.log(pem); // <-- This is what you want!
    console.log();

    // write it to a file
    var fname = './user_certs/' + cert.serialNumber + '.pem'
    fs.writeFileSync(fname, pem);
}

exports.genX509CertWithSubjAltName = genX509CertWithSubjAltName;


genX509CertWithSubjAltName();