// Node.js program to demonstrate the  
// x509.subjectAltName function
  
// Importing crypto module
const {X509Certificate} = require('crypto');
  
// Importing fs module
const fs = require('fs');

  function getSubAltName(cert) {
    // getting object of a PEM encoded X509 Certificate. 
    const x509 = new X509Certificate(fs.readFileSync('publiccert.pem'));
    
    // getting subjectAltName included in this certificate.
    // by using x509.subjectAltName function
    const value = x509.subjectAltName;
    
    // display the result
    console.log("subjectAltName :- " + value);
  }

  getSubAltName('');