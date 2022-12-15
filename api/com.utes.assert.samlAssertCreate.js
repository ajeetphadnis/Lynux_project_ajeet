/**
 * Project: com.utes.cert.crypto
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * https://github.com/auth0/node-saml
 * 
 */
require('dotenv').config();
var saml = require('saml').Saml20; // or Saml11
var XMLSerializer = require('xmldom').XMLSerializer;
var fs = require('fs'); 
var options = new Object();


var debug = process.env.DEBUG22;
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
function  createSamlAssert(uid, opts, req, res, next) {
	//console.log("Assert2: " + opts.cert); 
	var signedAssertion = saml.create(opts);
	if(debug) {console.log("Assert3: " + JSON.stringify(signedAssertion));}
	//var xmlStr = new XMLSerializer().serializeToString(signedAssertion);
	fs.writeFileSync("./user_certs/"+uid+"_signedAssert.xml", signedAssertion, function(err, signedAssertion) {
	    if (err) {
	      console.log("err")
	    } else {
	      console.log("Xml file successfully updated.");
	      return JSON.stringify(signedAssertion);
	    }
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
function  createDemoSamlAssert(uid, opts, req, res, next) {
	//console.log("Assert2: " + opts.cert); 
	var signedAssertion = saml.create(opts);
	if(debug) {console.log("Assert Demo: " + JSON.stringify(signedAssertion));}
	//var xmlStr = new XMLSerializer().serializeToString(signedAssertion);
	fs.writeFileSync("./demo_certs/"+uid+"_signedAssert.xml", signedAssertion, function(err, signedAssertion) {
	    if (err) {
	      console.log("err")
	    } else {
	      console.log("Xml file successfully updated.");
	      return JSON.stringify(signedAssertion);
	    }
	  });
}

exports.createSamlAssert = createSamlAssert;
exports.createDemoSamlAssert = createDemoSamlAssert;
exports.options = options;
