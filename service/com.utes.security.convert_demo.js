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
const selfsignedCert = require('../x509_utils/com.utes.security.createDemoSelfSignedCert');
const Users =  require("../models/com.utes.auth.users");
const assert = require('../saml_assert/com.utes.saml.user_initiated');
const dashRE = /-/g;
const lodashRE = /_/g;


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

user = {
  uid: '',
  pass: '',
  serv: '',
  srctxt: '',
  destxt: '',
  oprf: '',
  oprt: '',
  newuser: {}
};


	/**
	 * 
	 * @param ms
	 * @returns
	 */
	function sleep(ms) {
		  return new Promise((resolve) => {
		    setTimeout(resolve, ms);
		  });
	}


	/**
	 * convrt_demo: 
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function convrt_demo (req, res, next) {
			req.app.set("../views", path.join(__dirname));
			req.app.set("view engine", "ejs");
			const { check, validationResult } = require('express-validator');
			var urlencodedParser = bodyParser.urlencoded({ extended: true });
			// get AJAX sent data
			if (req.method === 'GET' && req.method !== 'POST') {
				if(debug) {console.log('GET');}
				req.on('data', function (chunk) {
			        console.log('GOT DATA!' + JSON.stringify(data));
			    });
			}
			
			if (req.method === 'POST' && req.method !== 'GET') {
				console.log('POST');
				if(debug) {console.log('Got body:', req.body);}
				var udat = JSON.parse(JSON.stringify(req.body.udata));
				JSON.parse(udat, (key, value) => {
					  if (typeof value === 'string') {
					    console.log("key:  " + key + "  value:  " + value);
					    if(key === 'uid') user.uid = value;
					    if(key === 'ope') user.oprf = value;
					    if(key === 'upass') user.pass = value;
					  }
					  //return value;
					  user.serv = user.oprf;
					});
			}
			var randusr = JSON.stringify(user.newuser);
			//
			//var filjwt = './samlIdpResp2jwt_rsa_signed.jwt';
			var filjwt = './demo_certs/';
			var filsaml = './demo_certs/';
			var filpem = './demo_certs/';
			//await res.status(200).send({ user: user});
	//		res.render("../views/demo_user",
	//                {
	//                    user: user,
	//                    randusr: randusr
	//                }
	//            );
	//		user.uid = uid;
	//		user.serv = opr;
	//		user.pass = upass
			opr = user.oprf;
			user.newuser.nameIdentifier = user.uid;
			user.newuser.password = user.pass;
			user.newuser.commonName = 'utesdemo.com';
			user.newuser.orgName = 'utesdemo.com';
			console.log("user id:  " + user.uid + "   pass:  " + user.pass);
			var convrt = 'convrt';
			var undef;
	
			var signingKey = secureRandom(256, { type: 'Buffer' }); // Create a highly random byte array of 256 bytes
			console.log("uid  :  " + user.uid + "    user.serv: " + user.oprf);
			//res.sendFile(path.join(__dirname,'../views/SampleForm.ejs'));
			if (!user.uid) {
				console.log("user id:  is null returning null" );
				return null;
			}
			if (user.uid && typeof user.uid !== undefined && user.uid != null && typeof opr !== undef && opr !== null && user.pass !== '') {			
				//Do Something
				var myHtmlData;
				var msg;
				var email1 = "ajeet.phadnis@dfo.no";
				var samlA;
				var x509Token;
				var pass = user.pass;
				user.newuser.commonName = 'utesdemo.com';
				user.newuser.orgName = 'utesdemo.com';
				user.newuser.password = user.pass;
				console.log("demo_user:   " + user.newuser.commonName);
				if (opr === 'SAML-OAuth') {
					await fs.readFile((filsaml+user.uid+'_signedAssert.xml'), (err, data) => {
					    if(err) {
					        //throw err;
							alert(filsaml+user.uid+'_signedAssert.xml ' + "file is not available try later.")
					    } else {
							user.srctxt = data.toString('utf8');
							user.oprf = 'Converting from SAMLToken -> JWT Token';
							//console.log("PostService:  000:  " +  user.jwtoken);
				        } 
					});
					var jwtFil = filjwt+user.uid+'_pem2jwks.jwt';
					await fs.readFile(jwtFil, (err, data) => {
					    if (err) {
							if (err.code === 'ENOENT') {
							  console.log('File not found!');
							} else {
							  throw err;
							}
					    } else {
							user.destxt = data.toString('utf8');
							//console.log("PostService:  000:  " +  user.jwtoken);
				        } 
					});
				}
				
				if (opr === 'OAuth-SAML') {
					//console.log("PostService:  001:  " + ret);
					await fs.readFile('./demo_certs/'+user.uid+'_pem2jwks.jwt', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.srctxt = data.toString('utf8');
						}
						
					});
					await fs.readFile('./demo_certs/'+user.uid+'_signedAssert.xml', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.destxt = data.toString('utf8');
						}
						
						});
				}
	
				if (user.serv === 'OAuth-X509') {
					user.newuser.commonName = 'utesdemo.com';
					user.newuser.orgName = 'utesdemo.com';
					user.newuser.password = user.pass;
					//var ret = await jwtks2pem.jwtks2pem(user.uid, (filjwt+user.uid+'_pem2jwks.jwt'), user.newuser, req, res, next);
					var jwtFil = filjwt+user.uid+'_pem2jwks.jwt';
					user.oprt = 'Converting from JWT Token -> X509 Certificate';
					await fs.readFile(jwtFil, 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.srctxt = data.toString('utf8');
	
						}
						
						});
					await fs.readFile('./demo_certs/'+user.uid+'_selfsigned.crt', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.destxt = data.toString('utf8');
						}
						
						});
				}
				if (user.serv === 'X509-OAuth') {
					console.log("Convert_Demo:X509-OAuth:  " user.uid);
					filpem = './demo_certs/'+user.uid+'_selfsigned.crt';
					filPrvKey = './demo_certs/'+user.uid+'_certp12b64.p12';
					user.newuser.password = user.pass;
					var jwt = await pem2jwks.cre_pem2jwt(user.uid, filPrvKey, filpem, user.pass, '', req, res, next);
					user.oprt = 'Converting from X509 Certificate -> JW Token';
					await fs.readFile('./demo_certs/'+user.uid+'_pem2jwks.jwt', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							//console.log("Converter:004: " + data);
							user.destxt = data;
						}
							
						});
					await fs.readFile('./demo_certs/'+user.uid+'_selfsigned.crt', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							//var tmpDt = data.replaceAll("\"", "");
							var tmpDt = data.replaceAll("^\"|\"$", "");
							var tmpDt1 = tmpDt.replace(/(\r\n|\n|\r)/gm,"");
							user.srctxt = tmpDt1;
							if(debug) {console.log("Converter:004: " + user.srctxt);}
	
						}
						
						});
				}
				if (user.serv === 'X509-SAML') {
					filpem = './demo_certs/'+user.uid+'_selfsigned.crt';
					user.newuser.password = user.pass;
					user.oprt = 'Converting from X509 Certificate -> SAML';
					await fs.readFile(filpem, 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							//console.log("Converter:004: " + data);
							user.srctxt = data.toString('utf8');
						}
						
						});
					await fs.readFile('./demo_certs/'+user.uid+'_signedAssert.xml', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.destxt = data.toString('utf8');;
							if(debug) {console.log("Converter:004: " + user.srctxt);}
	
						}
						
						});
				}
				if (user.serv === 'SAML-X509') {
					filpem = './demo_certs/'+user.uid+'_selfsigned.crt';
					user.newuser.password = user.pass;
					user.oprt = 'Converting from X509 Certificate -> SAML';
					await fs.readFile(filpem, 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							//console.log("Converter:004: " + data);
							user.destxt = data.toString('utf8');
						}
						
						});
					await fs.readFile('./demo_certs/'+user.uid+'_signedAssert.xml', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.srctxt = data.toString('utf8');;
							if(debug) {console.log("Converter:004: " + user.srctxt);}
	
						}
						
						});
				}
				sleep(100000000);
				//await console.log("srctxt:  " + user.srctxt + "    destxt:   " + user.destxt);
				await res.status(200).send({ user: user});
	//			res.render("../views/demo_user",
	//	                {
	//	                    user: user,
	//	                    randusr: randusr
	//	                }
	//	            );
	        }
		}
exports.convrt_demo = convrt_demo;