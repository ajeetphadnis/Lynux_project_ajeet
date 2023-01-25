/**
 * http://usejsdoc.org/
 */
require('dotenv').config();
const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const path = require('path');
const formidable = require("formidable");
const fileUpload = require('express-fileupload');
var select = require('xml-crypto').xpath
  ,	xpath = require('xpath')
  , dom = require('xmldom').DOMParser
  , SignedXml = require('xml-crypto').SignedXml
  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
  , fs = require('fs')
  , fsp = require('fs').promises;
var session;
const Users =  require("../models/com.utes.auth.users");
var jose = require('node-jose');
var forge = require('node-forge');
var privateKeyP12Pem;
var certP12Pem;
var status = false;
var keyinfo;
var certSN;
var kinf;
var endStr = `
	</ApplicationRequest>`;
var jfpath;
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

var certSN;
var pars;
var fil;
var resHdr = false;
var fName;
var jfpath;
var debug;

var debug = process.env.DEBUG1;
	if (debug === 'true') {
		debug = 'true';
	} else {
		debug = null;
	}


	/**
	 * getP12FileName: Serches for p12 file in supplied directory
	 * and the user in arg strtStr
	 *  
	 * @param firstname
	 * @returns file path
	 * 
	 */
	function getP12FileName(dir, strtStr, endStr) {
		//const dir = '/Users/flavio/folder'
		const files = fs.readdirSync(dir);
		
		for (const file of files) {
			if (file.startsWith(strtStr) && file.endsWith(endStr)) {
				//console.log(file);
				return file;
			}	  
		}
	}


	/**
	 * readFile: reads file in supplied filepath
	 * with a promise
	 *  
	 * @param firstname
	 * @returns
	 * 
	 */
	const readFile = (filePath, encoding) => {
	    return new Promise((resolve, reject) => {
	        fs.readFile(filePath, encoding, (err, data) => {
	            if (err) {
					console.log("No file found !!");
	                //return reject(err);
	            }
	            resolve(data);
	            if(debug) {console.log(data.toString());}
				if(data) {
	            	return data.toString();
				} else {
					return("No data read !!");
				}
	        });
	    });
	}

	
	/**
	 * getSubSerialNr: generates serial number
	 * secure envelop
	 *  
	 * @param firstname
	 * @returns serial number
	 * 
	 */
	function getSubSerialNr() {
		var sn = Math.floor(Math.random() * 900000);
		if(debug) {console.log("SN:  " + sn);}
		var dt = new Date();
		mm = (dt.getMonth() + 1).toString().padStart(2, "0");
		dd   = dt.getDate().toString().padStart(2, "0");
		var sn =sn+'-'+mm+dd;
		if(debug) {console.log('snum:  ' + sn);}
		return sn;
	}



	/**
	 * readP12PrvKey : analyses the user p12 file and then extracts
	 * private key and public certificate and uses them to create
	 * secure envelop and signs it.
	 * @param firstname
	 * @returns secure envelop
	 * 
	 */
	const readP12PrvKey = async (clntData, clntId, filePath, pass, fileEnv, req) => {
		filePath = filePath.replace(/\s/g, "") ;
		console.log("readP12PrvKey001:  " + filePath + "    " + pass);
		try {
			if (filePath && clntId) {
				if(debug) {console.log("readP12PrvKey:clntData:  " + JSON.stringify(clntData));}
				if(debug) {console.log("readP12PrvKey:clntId:  " + clntId);}
				if(debug) {console.log("readP12PrvKey:filePath:  " + filePath);}
				if(debug) {console.log("readP12PrvKey:pass:  " + pass);}
				if(debug) {console.log("readP12PrvKey:fileEnv:  " + fileEnv);}
				// read payload file
				var payload = await readFile('./demo_certs/Pain001.xml');
				var b64Str = Buffer.from(payload).toString('base64');
				// read client p12 file
				var keyFile = await fs.readFileSync(filePath, 'binary');
				var p12Asn1 = await forge.asn1.fromDer(keyFile, false);
				var p12 = await forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, pass);
				// get key bags
				// load keypair and cert chain from safe content(s) and map to key ID
				  var map = {};
				  for(var sci = 0; sci < p12.safeContents.length; ++sci) {
				    var safeContents = p12.safeContents[sci];
				    if(debug) {console.log('safeContents ' + (sci + 1));}
			
				    for(var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
				      var safeBag = safeContents.safeBags[sbi];
				      if(debug) {console.log('safeBag.type: ' + safeBag.type);}
			
				      var localKeyId = null;
				      if(safeBag.attributes.localKeyId) {
				        localKeyId = await forge.util.bytesToHex(
				          safeBag.attributes.localKeyId[0]);
				        if(debug) {console.log('localKeyId: ' + localKeyId);}
				        if(!(localKeyId in map)) {
				          map[localKeyId] = {
				            privateKey: null,
				            certChain: []
				          };
				        }
				      } else {
				        // no local key ID, skip bag
				        continue;
				      }
			
				      // this bag has a private key
				      if(safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
				        if(debug) {console.log('found private key');}
				        map[localKeyId].privateKey = safeBag.key;
				      } else if(safeBag.type === forge.pki.oids.certBag) {
				        // this bag has a certificate
				        if(debug) {console.log('found certificate');}
				        map[localKeyId].certChain.push(safeBag.cert);
				      }
				    }
				  }
			
				  if(debug) {console.log('\nPKCS#12 Info:');}
			
				  for(var localKeyId in map) {
				    var entry = map[localKeyId];
				    if(debug) {console.log('\nLocal Key ID: ' + localKeyId);}
				    if(entry.privateKey) {
				      privateKeyP12Pem = await forge.pki.privateKeyToPem(entry.privateKey);
				      var encryptedPrivateKeyP12Pem = await forge.pki.encryptRsaPrivateKey(entry.privateKey, pass);
			
				      if(debug) {console.log('\nPrivate Key:');}
				      if(debug) {console.log(privateKeyP12Pem);	    }  
				      fs.writeFile('./demo_certs/'+user.uid+'_prvKey.pem', privateKeyP12Pem, function (err, file) {
							//if (err) throw err;
							console.log('Saved  privKey.pem file!');
						});
				      if(debug) {console.log('Encrypted Private Key (password: "' + pass + '"):');}
				      // console.log(encryptedPrivateKeyP12Pem);
				      if(entry.certChain.length > 0) {
					      if(debug) {console.log('Certificate chain:');}
					      var certChain = entry.certChain;
					      for(var i = 0; i < certChain.length; ++i) {
					        certP12Pem = await forge.pki.certificateToPem(certChain[i]);
					        if(debug) {console.log("x509Cert:  " + certP12Pem);}
					        var remHeaderCert = certP12Pem.replace('-----BEGIN CERTIFICATE-----', '');
					        remHeaderCert = remHeaderCert.replace('-----END CERTIFICATE-----', '');
					        remHeaderCert = remHeaderCert.replace(/\r?\n|\r/g, "");
					        const cert = await forge.pki.certificateFromPem(certP12Pem);
					        const subject = cert.subject.attributes
					          .map(attr => [attr.shortName, attr.value].join('='))
					          .join(', ');	
					        if(debug) {console.log(subject); }// "C=US, ST=California, ..."
					        //user.uid = clntData.CustomerId;
					        //user.TargetId = clntData.TargetId;
					        // var b64Str = Buffer.from("This is test
							// string").toString('base64');
							//user = req.session.user;
							xfile = fs.readFileSync(jfpath, 'utf8');
							//console.log("p12Cert:  " + xfile);
							user.Content = xfile;
					        //console.log("User Content:  " + user.Content);
					        var b64Str = Buffer.from(user.Content).toString('base64');
					        user.Content = b64Str;
					        user.keyInfo = keyinfo;
					     // version
					        if(debug) {console.log(cert.version);}
					        // serial number
					        certSN = getSubSerialNr();
					        if(debug) {console.log(certSN);}
					        // validity
					        if(debug) {console.log(cert.validity['notBefore']);}
					        // issuer
					        // all issuer attributes
					        var issuAttrs = JSON.stringify(cert.issuer.attributes);
					        var issuVals = JSON.parse(issuAttrs);
					        if(debug) {console.log('IssuerAttrs:   ' + JSON.stringify(issuVals['CN']));}
					        // get, for example, common name via its short name "CN"
					        if(debug) {console.log(cert.issuer.getField('CN').value);}
					        if(debug) {console.log(cert.issuer.getField('C'));}
					        // subject
					        if(debug) {console.log(cert.subject);}
					        // all subject attributes
					        if(debug) {console.log(cert.subject.attributes);}
					        // get, for example, common name via its short name "CN"
					        if(debug) {console.log(cert.subject.getField('CN'));}
					        cnName = cert.subject.getField('CN').toString();
					        var issuerStr = 'SERIALNUMBER='+certSN+','+'CN='+cert.issuer.getField('CN').value+','+'O='+cert.issuer.getField('O').value+','+'C='+cert.issuer.getField('C').value;
					        keyinfo = 
					        	`<X509IssuerSerial><X509IssuerName>`+issuerStr+`</X509IssuerName><X509SerialNumber>`+certSN+`</X509SerialNumber></X509IssuerSerial><X509Certificate>`+remHeaderCert+`</X509Certificate>`;
					        await fs.writeFile('./demo_certs/'+user.uid+'_Cert.pem', certP12Pem, function (err, file) {
								//if (err) throw err;
								console.log('Saved  user_Cert.pem file!');
							});
					      }
				      }
				    }
				  }
				}
			}  catch (e) {
			    console.log('e', e);
			    status = false;
			}
		  if (filePath === undefined) {
		    console.log('filePath undefined');
		    status = false;
		  } else {
		    console.log('filePath', filePath);
		    status = true;
		  }
		  if (status) {
			  try {
				  var tempEnv = await fs.readFileSync(fileEnv, 'binary');
				  if(debug) {console.log('tempEnv:  ' + tempEnv);}
				  var xmlStr = await envModifyXml(tempEnv, user);
				  if(debug) {console.log("xml with sig:   " + xmlStr);}
				// sign an xml document
				var signedXml1 = await signXml(xmlStr, "//*[local-name(.)='Content']",  "./demo_certs/"+user.uid+"_prvKey.pem", "./secure_envelop/ApplicationRequest.xml");	
				//var signedXml = fs.readFileSync("./secure_envelop/ApplicationRequest.xml").toString();
				user.secenv = signedXml1;
				req.session.signedXml = signedXml1;
				if(debug) {console.log("xml signed succesfully: 00001   " + session);}
				// validate an xml document
				// var ret = await validateXml(signedXml, certP12Pem);
				if (await validateXml(session, "./demo_certs/"+user.uid+"_Cert.pem") ) {				
				  if(debug) {console.log("signature is valid:   " );}
				  return session;
				} else {

				  console.log("signature not valid:   " );
				  return session;
				}
			  } catch (e) {
				    console.log('e', e);
				    status = false;
				}
		  }	  
	}

	/**
	 * processForm : analyses the user p12 file and then extracts
	 * private key and public certificate and uses them to create
	 * secure envelop and signs it.
	 * @param firstname
	 * @returns secure envelop
	 * 
	 */
	async function processForm(form, req, res) {
		var filStr;
		if (form ) {
			const uploadFolder = path.join("./uploads");
			console.log("processForm:uploaderPath:  " + uploadFolder);
			const form = formidable({ multiples: true });
			form.multiples = true;
			form.maxFileSize = 50 * 1024 * 1024; // 5MB
			form.uploadDir = uploadFolder;
			form.encoding = 'utf-8';
			var formfields = new Promise(function (resolve, reject) {
		        form.parse(req, function (err, fields, files) {
		            if (err) {
		                reject(err);
		                return;
		            }
		            //console.log("within form.parse method, subject field of fields object is: " + fields.subjects);
		            resolve(fields);
		            resolve(files);
		            pars = JSON.parse(JSON.stringify(fields));
		            fil = JSON.parse(JSON.stringify(files));
		            if (files && fil.Content) {
			            jfpath = JSON.stringify(fil.Content.filepath);
			            jfpath = jfpath.replace(/[\[\]'"]/gi, '');
			            fName = JSON.stringify(fil.Content.newFilename);
			            if(debug) {console.log("POST:   " + jfpath);}
			            if(debug) {console.log("POST:   " + fName);}
					    pars = JSON.parse(JSON.stringify(fields));
					    if(debug) {console.log("POST4:   " + JSON.stringify(pars));}
					    user.uid = pars.uid11;
					    user.pass = pars.uid11;
					    user.target = pars.target;
					    user.filetype =pars.filetype;
					    if(debug) {console.log("POST5:   " + user.uid);}
						if(debug) {console.log("getDemoUserSecureEnv001:   called ...." + user.uid);}
						user.newuser = new Users();
						user.newuser.nameIdentifier = user.uid;
						user.newuser.password = user.pass;
						user.newuser.commonName = 'utesdemo.com';
						user.newuser.orgName = 'utesdemo.com';
						// ksVals.CustomerId = user.uid;
						uid = user.uid;
						if(debug) {console.log("getDemoUserSecureEnv:POST:  " + uid);}
						if(debug) {console.log('ClientId:   ' +user.uid+ "      :   " + user.target + "     :   " + user.filetype );}
						req.app.session.clnt = user.uid;
						req.app.session.target = user.target;
						req.app.session.ftype = user.filetype;
						if(debug) {console.log("getDemoUserSecureEnv:Mutler Middleware002: Present:  " + __dirname);}
						if(debug) {console.log("POSTFilePath:   " + jfpath);}
						user.Content = fs.readFileSync(path.join(__dirname, '../'+jfpath));
						console.log("getDemoUserSecureEnv:Post:  " + user.uid + "    " + JSON.stringify(user.Content));
						if(user.uid) {
							var fname = getP12FileName('./demo_certs/', user.uid, '_certp12b64.p12');
							fname = fname.replace(/\s/g, "");
							if(debug) {console.log("user p12 file name:  " + fname);		}					
							readP12PrvKey(user, user.uid, './demo_certs/'+fname, user.pass, './secure_envelop/nordea_EnvelopeTemplate.xml');
							var signedXml = fs.readFileSync("./secure_envelop/ApplicationRequest.xml").toString();
							//console.log("client_secureEnv:  newenvVals: " + user);
							user.secenv = signedXml.toString();				
					    } else {
					    	console.log("user id is empty !!");
					    }
		            }
					try {
						console.log("Delete file: ");
						var fpath = path.join(__dirname, '../uploads');
						fs.readdir(fpath, (err, files) => {
							  //if (err) throw err;
							  for (const file of files) {
							    fs.unlink(path.join(fpath, file), err => {
							    	console.log("Deleted file:   " );
							      //if (err) throw err;
							    });
							  }
							});					
					} catch(err) {
					  console.error(err)
					}
		        }); // form.parse
		    });
			} else {
			console.log("Form data is empty !!");
		}
	}


	/**
	 * processForm : analyses the user p12 file and then extracts
	 * private key and public certificate and uses them to create
	 * secure envelop and signs it.
	 * @param firstname
	 * @returns secure envelop
	 * 
	 */
		 async function processExtForm(form, req, res) {
			var filStr;
			if (form ) {
				//session = req.session;
				const uploadFolder = path.join("./uploads");
				console.log("processExtForm001:uploaderPath:  " + uploadFolder);
				const form = new formidable.IncomingForm();
				//const form = formidable({ multiples: true });
				form.multiples = true;
				form.maxFileSize = 50 * 1024 * 1024; // 5MB
				form.uploadDir = uploadFolder;
				form.encoding = 'utf-8';
				//console.log("processExtForm002:  " + session.uname);
				var formfields = new Promise(async function (resolve, reject) {
					form.parse(req, async function (err, fields, files) {
						if (err) {
							console.log("processExtForm003:  ");
							reject(err);
							return;
						}
						//console.log("processExtForm004:  "+ session.user);
						//console.log("within form.parse method, subject field of fields object is: " + fields.subjects);
						resolve(fields);
						if(debug) {console.log("processExtForm005:  " + JSON.stringify(fields))};
						resolve(files);
						if(debug) {console.log("processExtForm006:  " + JSON.stringify(files))};
						//pars = JSON.parse(JSON.stringify(fields));
						if(debug) {console.log("processExtForm007:  ")};
						fil = JSON.parse(JSON.stringify(files));
						if(debug) {console.log("processExtForm008:  " + JSON.stringify(fil))};
						if (files && fil.Content) {
							if(debug) {console.log("processExtForm009:  ")};
							jfpath = JSON.stringify(fil.Content.filepath);
							jfpath = jfpath.replace(/[\[\]'"]/gi, '');
							fName = JSON.stringify(fil.Content.newFilename);
							// bypass the Open/Save/Cancel dialog
							if (!resHdr) {
								//res.setHeader("Content-Disposition", "inline; filename=" + fName);
								res.setHeader("Content-Type", "text/xml");
								res.setHeader( "Content-Disposition", "filename=" + fname );
								resHdr = true;
							}
							jfpath = __dirname+'/'+'../uploads/'+fName;
							jfpath = jfpath.replace(/[\[\]'"]/gi, '');
							if(debug) {console.log("processExtForm010:   " + jfpath)};
							//console.log("processExtForm011:   " + fName);
							pars = JSON.parse(JSON.stringify(fields));
							if(debug) {console.log("POST4:   " + pars.uid11)};
							//req.session.user = user;
							user.uid = pars.uid11;
							user.pass = pars.uid11;
							user.target = pars.target;
							user.filetype =pars.filetype;
							if(debug) {console.log("processExtForm012:   " + user.uid)};
							user.newuser = new Users();
							user.newuser.nameIdentifier = user.uid;
							user.newuser.password = user.pass;
							user.newuser.commonName = 'utesdemo.com';
							user.newuser.orgName = 'utesdemo.com';
							// ksVals.CustomerId = user.uid;
							//req.session.user = user;
							uid = user.uid;
							//console.log("processExtForm013:   " + JSON.stringify(req.session.user));
							if(debug) {console.log('processExtForm014   ' +user.uid+ "      :   " + user.target + "     :   " + user.filetype )};
							//req.app.session.clnt = user.uid;
							//req.app.session.target = user.target;
							//req.app.session.ftype = user.filetype;
							if(debug) {console.log("getDemoUserSecureEnv:Mutler Middleware002: Present:  " + __dirname);}
							if(debug) {console.log("POSTFilePath:   " + jfpath);}
							//user.Content = fs.readFileSync(path.join(__dirname, '../'+jfpath));
							//user.Content = fs.readFileSync((path.join(__dirname, '../'+jfpath)), 'utf-8');
							if(debug) {console.log("getDemoUserSecureEnv:Post:  " + user.uid + "    " + JSON.stringify(user.Content))};
							if(user.uid) {
								var fname = getP12FileName('./demo_certs/', user.uid, '_certp12b64.p12');
								if(debug) {console.log("user p12 file name:  " + fname);		}					
								await readP12PrvKey(user, user.uid, './demo_certs/'+fname, user.pass, './secure_envelop/nordea_EnvelopeTemplate.xml', req);
								//var signedXml = fs.readFileSync("./secure_envelop/ApplicationRequest.xml").toString();
								//var signedXml = await readFile(("./secure_envelop/ApplicationRequest.xml").toString(), 'utf-8');
								//console.log("processExtForm015: secenv: " + user.secenv);
								//user.secenv = signedXml.toString();	
								//user.secenv = req.session.signedXml;
								//console.log("processExtForm015: req_session: " + JSON.stringify(req.session));
								//req.session.user = JSON.stringify(user);	
							} else {
								console.log("user id is empty !!");
							}
						}
						try {
							console.log("Delete file: ");
							var fpath = path.join(__dirname, '../uploads');
							fs.readdir(fpath, (err, files) => {
								  if (err) {
									console.log("no files to delete !!");
									//res.render('secenv', { user: user});
          							return user;
								  }
									//throw err;
								  for (const file of files) {
									fs.unlink(path.join(fpath, file), err => {
										console.log("Deleted file:   " );

									  if (err) if (err) {
										console.log("no files to delete !!");
										//res.render('secenv', { user: user});
          								return user;
									  }
									});
								  }
								});	
								return req.session;				
						} catch(err) {
						  console.error(err)
						  //res.sendStatus(500);
          				return;
						}
					}); // form.parse
				});
				return req.session;
				} else {
				console.log("Form data is empty !!");
				//res.sendStatus(500);
          		return user;
			}
			return req.session;
		}
	


	/**
	 * Function: getKeyInfo
	 * @returns
	 */
	function getKeyInfo() {
	  this.getKeyInfo = function(key, prefix) {
	    prefix = prefix || '';
	    prefix = prefix ? prefix + ':' : prefix;
	    kinf = "<" + prefix + "X509Data>"+keyinfo+"</" + prefix + "X509Data>";
		if(debug) {console.log("getKeyInfo:   " + kinf);}
	    return kinf;
	  }
	  this.getKey = function(keyInfo) {
	    // you can use the keyInfo parameter to extract the key in any way you want
	    return fs.readFileSync("./demo_certs/"+user.uid+"_prvKey.pem");
	  }
	}

	
	/**
	 * Function: signXml
	 * @param xml
	 * @param xpath
	 * @param key
	 * @param dest
	 * @returns
	 */
	async function signXml(xml, xpath, key, dest) {
	  var sig = new SignedXml();  
	  if(debug) {console.log("signXml001:   " );}
	  sig.keyInfoProvider = await new getKeyInfo();
	  // sig.keyInfoProvider = new
		// FileKeyInfo('./rsa_domain/Integration_Cert.pem');
	  sig.signingKey = await readFile(key);
	  if(debug) {console.log("signXml002:   ");}
	  await sig.addReference("//*[local-name(.)='Content']");
	  if(debug) {console.log("signXml003:   ");}
	  await sig.computeSignature(xml);
	  if(debug) {console.log("signXml004:   ");}
	  var xmlStr = sig.getSignedXml();
	  session = xmlStr;
	  if(debug) {console.log("signXml005:   " + xmlStr)};
	  fs.writeFileSync(dest, xmlStr);
	  return xmlStr;
	}

	
	/**
	 * Function: validateXml
	 * @param xml1
	 * @param key
	 * @returns
	 */
	async function validateXml(xml1, key) {
		try {
			xml = fs.readFileSync('./secure_envelop/ApplicationRequest.xml').toString();
			if(debug) {console.log('validateXml:signedXml:  ' + xml);}
		  var doc = await new dom().parseFromString(xml,"text/xml");    
		  var signature = select(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
		  var sig = new SignedXml();
		  if(debug) {console.log("validate result001:  ");}
		  // sig.addReference("//*[local-name(.)='Signature']",
			// ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
			// 'http://www.w3.org/2001/04/xmlenc#sha256');
		  sig.keyInfoProvider = new FileKeyInfo(key);
		  if(debug) {console.log("validate result002:  ");}
		  // await sig.loadSignature(signature.toString());
		  if(debug) {console.log("validate result003:  ");}
		  sig.loadSignature(signature);
		  if(debug) {console.log("validate result004:  ");}
		  var res = sig.checkSignature(xml);
		  if(debug) {console.log("validate result005:  " + res);}
		  if (!res) console.log(sig.validationErrors);
		  if(debug) {console.log("validate result006:  " + res);}
		  return res;
		} catch (e) {
		    // console.log('e', e);
		    status = false;
		}  
	}

	
	
	/**
	 * envModifyXml: how the node values are used:
	 * nodeValue on an element will return null. However on a text node it will
	 * return the value.
	 * Since text is treated as a node you need to select another childnode.
	 * textContent gives you all the text inside the element.
	 * Different node-types. Text inside a node is treated as a text-node.
	 * That's why nodeValue on the element returned null. Table from MDN
	 * @param xml
	 * @param envData
	 * @returns
	 */
	async function envModifyXml(xml, envData) {
		try {
			//console.log( "envModifyXml: xml: " + xml );
			var parser = new dom();
			var document = parser.parseFromString( xml , "text/xml");
			// this won't work, but no error
			// document.getElementsByTagName("CustomerId")[0].childNodes[0].data =
			// "98765";
			document.getElementsByTagName('CustomerId')[0].textContent = user.uid;
			document.getElementsByTagName( "TargetId" )[0].textContent = user.target;
			txt = document.getElementsByTagName("SoftwareId")[0].childNodes[0].nodeValue;
			document.getElementsByTagName( "Content" )[0].textContent = user.Content;
			// document.getElementsByTagName( "KeyInfo" )[0].textContent =
			// envData.keyInfo;
			if(debug) {console.log( "SoftwareId: " + txt);}
			var XMLSerializer = require( 'xmldom' ).XMLSerializer;
			var serializer = new XMLSerializer();
			var xmlstring = serializer.serializeToString( document );
			if(debug) {console.log( "xmlstring: " + xmlstring );}
			return xmlstring;
		} catch (e) {
		    console.log('e', e);
		    status = false;
		}
	}




	/**
	 * getDemoUserSecureEnv: This function captures the http methods
	 * Get and Post with client requests. When a POST request is received
	 * it collects the user information and generates all the relevant 
	 * certificates and tokens and finally generates the secure envelop
	 * and sends it back to client.
	 * @param firstname
	 * @returns
	 * 
	 */
			 async function getDemoUserSecureEnv(req, res, next) {
				try {
					if (req.method === 'GET' && req.method !== 'POST') {
						req.app.use(bodyParser.urlencoded({ extended : true }));
						var data = JSON.stringify(req.session.user);
						console.log('GET');
						//res.render('demo_user', {data: data});
						//res.redirect(req.get('referer'));
						//req.on('data', function (chunk) {
						if(debug) {console.log("Get:  "  + data);}
							//console.log('getDemoUserSecureEnv:GET DATA!' + JSON.stringify(data));
						//});
					}		
					if (req.method === 'POST' && req.method !== 'GET') {						
						const uploadFolder =  "./uploads";
						console.log("POSTFunc:uploaderPath:  " + uploadFolder);
						const form = formidable({ multiples: true });
						form.multiples = true;
						form.maxFileSize = 50 * 1024 * 1024; // 5MB
						form.uploadDir = uploadFolder;
						await processExtForm(form, req, res);
						if(debug) {console.log("SecureEnv:  " + JSON.stringify(user));}
						
						if (user && user.uid) {
							if(debug) {console.log("POST: user:   " + JSON.stringify(user));}
							req.app.session = req.session;
							req.app.session.user = JSON.stringify(user);
							//await res.status(200).send({ user: user});
							//let ejs = require('ejs');
							randusr = JSON.stringify(user);
							res.setHeader('Content-type','multipart/form-data')
							if(debug) {console.log("POST: response:   " + JSON.stringify(user));}
							req.body.secenv = JSON.stringify(user);
							//res.render('demo_user', {user: user, randusr: randusr});							
							await res.status(200).send({ user});
							//res.redirect(req.get('referer'));
						}
					}
				} catch (err) {
					console.log(err);
				}
			}
		



exports.readP12PrvKey = readP12PrvKey;
exports.processForm = processForm;
exports.processExtForm = processExtForm;
exports.getDemoUserSecureEnv = getDemoUserSecureEnv;
//exports.getSecEnv = getSecEnv;
//module.exports = router;

// readP12PrvKey('', 'OktaUser',
// './rsa_domain/Integration_grp_integration_cert.p12', 'Integration_grp',
// './crypto_xml/nordea_EnvelopeTemplate.xml');