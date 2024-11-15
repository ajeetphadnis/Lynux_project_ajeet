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
var crAssert = require('./com.utes.assert.samlAssertCreate');
var fs = require('fs'); 
const Users =  require("../models/com.utes.auth.users");
var usrDb = require('../models/com.utes.mongo.crud');
var usrStruct = require('../models/com.utes.mongo.crud');



var debug = process.env.DEBUG14;
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
	 * getSamlAssert: 
	 * @param uid
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	function getSamlAssert(uid, req, res, next) {
		// db fetch start
		console.log("getSamlAssert001: " + uid);
		if (uid) {
        		connMongo(req, res);
        		usrDb.getUserStruct(uid, req, res, next).then(res => {
        			if (uid != null && uid != '') {
        				var data = JSON.stringify(usrStruct);
        				JSON.parse(data, (key, value) => {
        					  if (typeof value === 'string') {
        					    //console.log("key:  " + key);
        					    if(key === 'nameIdentifier') newuser.nameIdentifier = value;
        					    if(key === 'emailAddress') newuser.emailAddress = value;
        					    if(key === 'fullname') newuser.fullname = value;
        					    if(key === 'commonName') newuser.commonName = value;
        					    if(key === 'orgName') newuser.orgName = value;
        					    if(key === 'password') newuser.password = value;
        					    if(key === 'mobilePhone') newuser.mobilePhone = value;
        					    if(key === 'groups') newuser.groups = value;
        					  }
        					  //return value;
        					});
        				if(debug) {console.log("getSamlAssert:Exported: " + JSON.stringify(newuser));}
        				// db fetch end
        				crAssert.options.cert = fs.readFileSync('SamlAssertCert.pem');
        				crAssert.options.key = fs.readFileSync('SamlAssertKey.pem');
        				crAssert.options.issuer = 'idp.utes.com';
        				crAssert.options.lifetimeInSeconds =  '10800';
        				//crAssert.options.Conditions = 'https://utes.com/saml';
        				crAssert.options.audiences = 'https://utes.com/saml';
        				//crAssert.options.NotBefore = "2021-04-23T23:51:43.745Z";
        				//crAssert.options.NotOnOrAfter = "2021-04-23T23:51:43.745Z";
        				crAssert.options.recipient = 'https://utes.com/saml/recipient';
        				crAssert.options.inResponseTo = 'https://utes.com/saml/inresponseto';
        				crAssert.options.includeAttributeNameFormat = true;
        				crAssert.options.emailAddress = 'ajeet.phadnis@gmail.com';
        				crAssert.options.nameIdentifier = uid;
        				crAssert.options.sessionIndex = 'jskjflksjeouotui4548958';
        				crAssert.options.authnContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
        //				crAssert.options.attributes = {
        //					//'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        //					'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailAddress': 'ajeet.phadnis@gmail.com',
        //				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Ajeet Phadnis',
        //				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstName': 'Ajeet',
        //				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/lastName': 'Phadnis',
        //				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayName': 'Ajeet Phadnis',
        //				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilePhone': '+4740634044',
        //				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups': 'Admin'
        //				}
        				crAssert.options.attributes = {
        						//'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        						'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailAddress': newuser.emailAddress,
        					    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': newuser.fullname,
        					    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstName': newuser.commonName,
        					    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/lastName': newuser.orgName,
        					    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayName': newuser.fullname,
        					    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilePhone': newuser.mobilePhone,
        					    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups': newuser.groups
        					}
        
        				
        				//console.log("getSamlAssert001: " + crAssert.options.cert); 
        				crAssert.createSamlAssert(newuser.nameIdentifier, crAssert.options, req, res, next);
        			} else {
        				console.log("  User does not exist");
        			}}).catch(err => console.log(err)); 
		}
	}
	
	
	
	/**
	 * getDemoSamlAssert:  
	 * @param uid
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function getDemoSamlAssert(uid, req, res, next) {
		// db fetch start
		console.log("getDemoSamlAssert001: " + uid);
		if (uid === 'undefined') {
			console.log("getDemoSamlAssert: user undefined");
			return null;
		}
		if (uid !== 'undefined' && uid != null) {
			connMongo(req, res);
			console.log("getDemoSamlAssert:  " + uid);
			await usrDb.getUserStruct(uid, req, res, next).then(res => {
				if (uid != null && uid != '') {
					var data = JSON.stringify(usrStruct);
					JSON.parse(data, (key, value) => {
						if (typeof value === 'string') {
							//console.log("key:  " + key);
							if(key === 'nameIdentifier') newuser.nameIdentifier = value;
							if(key === 'emailAddress') newuser.emailAddress = value;
							if(key === 'fullname') newuser.fullname = value;
							if(key === 'commonName') newuser.commonName = value;
							if(key === 'orgName') newuser.orgName = value;
							if(key === 'password') newuser.password = value;
							if(key === 'mobilePhone') newuser.mobilePhone = value;
							if(key === 'groups') newuser.groups = value;
						}
						//return value;
						});
					if(debug) {console.log("getDemoSamlAssert:Exported: " + JSON.stringify(newuser));}
					// db fetch end
					crAssert.options.cert = fs.readFileSync('SamlAssertCert.pem');
					crAssert.options.key = fs.readFileSync('SamlAssertKey.pem');
					crAssert.options.issuer = 'idp.utes.com';
					crAssert.options.lifetimeInSeconds =  '10800';
					//crAssert.options.Conditions = 'https://utes.com/saml';
					crAssert.options.audiences = 'https://utes.com/saml';
					//crAssert.options.NotBefore = "2021-04-23T23:51:43.745Z";
					//crAssert.options.NotOnOrAfter = "2021-04-23T23:51:43.745Z";
					crAssert.options.recipient = 'https://utes.com/saml/recipient';
					crAssert.options.inResponseTo = 'https://utes.com/saml/inresponseto';
					crAssert.options.includeAttributeNameFormat = true;
					crAssert.options.emailAddress = 'ajeet.phadnis@gmail.com';
					crAssert.options.nameIdentifier = uid;
					crAssert.options.sessionIndex = 'jskjflksjeouotui4548958';
					crAssert.options.authnContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
	//				crAssert.options.attributes = {
	//					//'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
	//					'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailAddress': 'ajeet.phadnis@gmail.com',
	//				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Ajeet Phadnis',
	//				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstName': 'Ajeet',
	//				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/lastName': 'Phadnis',
	//				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayName': 'Ajeet Phadnis',
	//				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilePhone': '+4740634044',
	//				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups': 'Admin'
	//				}
					crAssert.options.attributes = {
							//'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
							'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailAddress': newuser.emailAddress,
							'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': newuser.fullname,
							'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstName': newuser.commonName,
							'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/lastName': newuser.orgName,
							'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayName': newuser.fullname,
							'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilePhone': newuser.mobilePhone,
							'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups': newuser.groups
						}

					
					//console.log("getSamlAssert001: " + crAssert.options.cert); 
					//connMongo(req, res);
					if (!newuser.nameIdentifier) {
						newuser.nameIdentifier = uid;
					}
					crAssert.createDemoSamlAssert(newuser.nameIdentifier, crAssert.options, req, res, next);

				} else {
					console.log("  User does not exist");
				}}).catch(err => {
					console.log(err)});
		} 		
	}
exports.getSamlAssert = getSamlAssert;
exports.getDemoSamlAssert =  getDemoSamlAssert;
