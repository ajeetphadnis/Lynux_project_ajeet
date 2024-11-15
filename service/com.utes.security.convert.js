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

require('dotenv').config();
const xmlParser 		  = require('xml2js'),
parseString 		  	  = require('xml2js').parseString,
//stripPrefix 			  = require('xml2js').processors.stripPrefix;
fs 						  = require('fs'),
util 					  = require('util'),
JWT 				  	  = require('jsonwebtoken'),
xmlParser1 				  = require('xml2json'),
formatXml 				  = require('xml-formatter'),
bodyParser 				  = require('body-parser');
//var jwtVerify = require('../api/com.utes.jwt_sign_verify');
var stripPrefix = require('xml2js').processors.stripPrefix;
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
const path = require('path');
var secureRandom = require('secure-random');
global.pubstr;
const jwtks2pem = require('./com.utes.jwtks-to-pem');
//const jwt2cert = require('../api/com.utes.jwt.cert');
//const pem2jwks  = require('./com.utes.pem-to-jwks');
const pem2jwks  = require('../jwks/com.utes.pem-to-jwt');
const jwksnew  = require('../jwks/com.utes.jwks.createJWKSNew');
//const saml2json = require('./com.utes.saml-to-json');
const idpsaml2jwt = require('./com.utes.idp.saml2jwt');
const jwt2Idpsaml = require('./com.utes.idp.jwt2saml');
const selfsignedCert = require('../x509_utils/com.utes.security.createUserSelfSignedCert');
const Users =  require("../models/com.utes.auth.users");
const assert = require('../saml_assert/com.utes.saml.user_initiated');
const dashRE = /-/g;
const lodashRE = /_/g;

var debug = process.env.DEBUG16;
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
  oprt: '',
  newuser: {}
};


	/**
	 * convrt:
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function convrt (req, res, next) {
			req.app.set("../views", path.join(__dirname));
			req.app.set("view engine", "ejs");
			const { check, validationResult } = require('express-validator');
			// call and create SAML Assert
			await assert.getSamlAssert(req.body.uid, req, res, next);
			// SAML Assert
			//create application/x-www-form-urlencoded parser
			var urlencodedParser = bodyParser.urlencoded({ extended: true });
			//var filjwt = './samlIdpResp2jwt_rsa_signed.jwt';
			var filjwt = './user_certs/';
			var filsaml = './user_certs/';
			var filpem = './user_certs/';
			res.render("../views/form_convrt",
	                {
	                    user: user
	                }
	            );
			user.uid = req.body.uid;
			user.serv = req.body.serv;
			user.pass = req.body.pass;
			user.newuser.nameIdentifier = user.uid;
			user.newuser.password = user.pass;
			user.newuser.commonName = 'utes.com';
			user.newuser.orgName = 'utes.com';
			console.log("user id:  " + user.uid + "   pass:  " + user.pass);
			var convrt = 'convrt';
			var undef;
	
			var signingKey = secureRandom(256, { type: 'Buffer' }); // Create a highly random byte array of 256 bytes
			console.log("uid  :  " + user.uid + "    user.serv: " + user.serv);
			//res.sendFile(path.join(__dirname,'../views/SampleForm.ejs'));
			if (!user.uid) {
				console.log("user id:  is null returning null" );
				return null;
			}
			if (user.uid && typeof user.uid !== undefined && user.uid != null && typeof user.serv !== undef && user.serv !== null && user.pass !== '') {			
				//Do Something
				var myHtmlData;
				var msg;
				var email1 = "ajeet.phadnis@dfo.no";
				var samlA;
				var x509Token;
				var pass = user.pass;
				user.newuser.commonName = 'utes.com';
				user.newuser.orgName = 'utes.com';
				user.newuser.password = user.pass;
				console.log("new_user:   " + user.newuser.commonName);
				await selfsignedCert.createUserSelfSignedCert(user.uid, '', user.newuser, user.pass, '', '', '');
				filpem = './user_certs/'+user.uid+'_selfsigned.crt';
				filPrvKey = './user_certs/'+user.uid+'_certp12b64.p12';
				await pem2jwks.cre_pem2jwt(user.uid, filPrvKey, filpem, user.pass, '', req, res, next);
				//console.log("jwtFileName:   " + filsaml);
				//var ret = jwt2Idpsaml.jwt2IdpSaml(fval, req, res, next);
				if (user.serv === 'serv1') {
					var ret = idpsaml2jwt.idpSaml2Jwt(user.uid, filsaml, req, res, next);
					user:uid = req.body.uid;
	//				res.render("../views/form_convrt",
	//		                {
	//		                    user: user
	//		                }
	//		            );
					fs.readFile((filsaml+user.uid+'_signedAssert.xml'), (err, data) => {
					    if(err) {
					        throw err;
					    } else {
							//req.body.jwtoken = data;
							user.srctxt = data;
							user.oprt = 'Converting from SAMLToken -> JWT Token';
							//console.log("PostService:  000:  " +  user.jwtoken);
				        } 
					});
					var jwtFil = filjwt+user.uid+'_pem2jwks.jwt';
					//fs.readFile('./samlIdpResp2jwt_rsa_signed.jwt', (err, data) => {
					fs.readFile(jwtFil, (err, data) => {
					    if (err) {
						if (err.code === 'ENOENT') {
						  console.log('File not found!');
						} else {
						  throw err;
						}
					    } else {
							//req.body.jwtoken = data;
							user.destxt = data;
							//console.log("PostService:  000:  " +  user.jwtoken);
				        } 
					});
					//user.x509token = 'SAML Token => JW Token';
				}
				
				if (user.serv === 'serv2') {
					var ret = jwt2Idpsaml.jwt2IdpSaml(user.uid, (filjwt+user.uid+'_pem2jwks.jwt'), req, res, next);
					user.srctxt = ret;
					user.destxt = global.jwstr;
					console.log("PostService:  000:  " +  user.jwtoken);
					fs.readFile('./user_certs/'+user.uid+'_signedAssert.xml', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.destxt = data;
						}
						
						});
					var jwtFil = filjwt+user.uid+'_pem2jwks.jwt';
					var jwtFil1 = './signedAssert.xml'
					//fs.readFile('./samlIdpResp2jwt_rsa_signed.jwt', 'utf8' , (err, data) => {	
					fs.readFile(jwtFil, 'utf8' , (err, data) => {
						if (err) {
							console.error(err);
							return;
						} else {
							const base64Url = data.split('.')[1];						  
							if (base64Url === undefined) return null;
							const base64 = base64Url.replace(dashRE, '+').replace(lodashRE, '/');
							var jsonStr = Buffer.from(base64, 'base64').toString();
							//console.log("parseJwtCrPem002: " + jsonStr);
							user.srctxt = jsonStr;
							user.oprt = 'Converting from JWT Token -> SAML Token';
						}
						
						});
					//user.x509token = 'JW Token => SAML Token';
				}
	
				if (user.serv === 'serv3') {
					user.newuser.commonName = 'utes.com';
					user.newuser.orgName = 'utes.com';
					user.newuser.password = user.pass;
					var ret = jwtks2pem.jwtks2pem(user.uid, (filjwt+user.uid+'_pem2jwks.jwt'), user.newuser, req, res, next);
					var jwtFil = filjwt+user.uid+'_pem2jwks.jwt';
					user.oprt = 'Converting from JWT Token -> X509 Certificate';
					fs.readFile(jwtFil, 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							const base64Url = data.split('.')[1];						  
							if (base64Url === undefined) return null;
							const base64 = base64Url.replace(dashRE, '+').replace(lodashRE, '/');
							var jsonStr = Buffer.from(base64, 'base64').toString();
							//console.log("parseJwtCrPem002: " + jsonStr);
							user.srctxt = jsonStr;
						}
						
						});
					fs.readFile('./user_certs/'+user.uid+'_selfsigned.crt', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.destxt = data;
						}
						
						});
				}
				if (user.serv === 'serv4') {
					filpem = './user_certs/'+user.uid+'_selfsigned.crt';
					filPrvKey = './user_certs/'+user.uid+'_certp12b64.p12';
					//var jwt = pem2jwks.pem2jwks(user.uid, filpem, req, res, next);
					//var payload = pem2jwks.getX509Details (user.uid, filpem, 'password');
					//console.log("Serv4:payload:   " + payload);
					user.newuser.password = user.pass;
					var jwt = pem2jwks.cre_pem2jwt(user.uid, filPrvKey, filpem, user.pass, '', req, res, next);
					user.oprt = 'Converting from X509 Certificate -> JW Token';
					fs.readFile('./user_certs/'+user.uid+'_pem2jwks.jwt', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							//console.log("Converter:004: " + data);
							user.destxt = data;
						}
						
						});
					fs.readFile('./user_certs/'+user.uid+'_selfsigned.crt', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							//console.log("Converter:004: " + data);
							user.srctxt = data;
						}
						
						});
				}
	        }
		}
exports.convrt = convrt;