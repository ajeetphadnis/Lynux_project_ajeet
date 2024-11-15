/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * 
 * 
 */
const fs = require('fs');
//var jwkToPem = require("jwk-to-pem")
var secureRandom = require('secure-random');
//var jwt = require('jsonwebtoken');
const selfsignedCert = require('../x509_utils/com.utes.security.createUserSelfSignedCert');
const dashRE = /-/g;
const lodashRE = /_/g;


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
	function parseJwtCrPem(token, uid, newuser) {
		  console.log("CERT: parseJwtCrPem001: "  + uid + "    newuser: " + newuser.commonName);
		  var token1 = token.toString();
		  
		  // get Private key for signing
//		  fs.readFile( './api/privatekey.pem', function(err, data) {
//				console.log("jwt2IdpSaml:  001");
//				if (err) {
//					console.log("error getting  file:    " + err.message);
//				}
//				prvStr = data;
//				console.log("jwt2IdpSaml:  002:   " + prvStr);
//				
//			});
		  // Get Token Header
		  const base64Url = token1.split('.')[1];
		  if (base64Url === undefined) return null;
		  const base64 = base64Url.replace(dashRE, '+').replace(lodashRE, '/');
		  var jsonStr = Buffer.from(base64, 'base64').toString();
		  console.log("parseJwtCrPem002: " + jsonStr);
		  var jwObj = JSON.parse(jsonStr);
		  jwObj.id = uid;
		  jwObj.sub = uid;
		  var ret = selfsignedCert.createUserSelfSignedCert(uid, '', newuser, newuser.password, '', '', '');
		  return ret;
	}
	exports.parseJwtCrPem = parseJwtCrPem;

