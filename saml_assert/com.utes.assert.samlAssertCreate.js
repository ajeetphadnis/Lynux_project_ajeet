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

var signedAssertion = '';

/**
 * Function: createSamlAssert
 * @param {*} uid 
 * @param {*} opts 
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
async function  createSamlAssert(uid, opts, req, res, next) {
	console.log("createSamlAssert001: " + uid);
	//console.log("createSamlAssert001: " + JSON.stringify(opts.attributes)); 
	signedAssertion = saml.create(opts);
	//console.log("createSamlAssert002: " + signedAssertion); 
	if(debug) {console.log("createSamlAssert003: " + JSON.stringify(signedAssertion));}
	var fpath = (__dirname+"\\.\\user_certs\\");
	//console.log("createSamlAssert002: " + (__dirname+"\\..\\user_certs\\"));
	//var xmlStr = new XMLSerializer().serializeToString(signedAssertion);
	//fs.writeFileSync("./user_certs/"+uid+"_signedAssert.xml", signedAssertion, function(err, signedAssertion) {
		fs.writeFile('./user_certs/'+uid+"_signedAssert.xml", signedAssertion, function(err) {
	    if (err) {
	      console.log("createSamlAssert004:err")
	    } else {
			console.log("createSamlAssert005:writefile:  success" )
	      //console.log("createSamlAssert005:Xml file successfully updated.    " + signedAssertion);
	    }
	  });
	  return signedAssertion;
}


/**
 * FUnction: createDemoSamlAssert
 * @param {*} uid 
 * @param {*} opts 
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
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
