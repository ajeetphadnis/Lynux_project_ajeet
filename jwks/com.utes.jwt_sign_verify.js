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
'use strict';
const fs = require('fs');
const jwt = require('jsonwebtoken');
const express=require('express');
const expr=express();
const bodyParser = require('body-parser');
var request = require('request');
// var nJwt = require('njwt');
var secureRandom = require('secure-random');
const path = require('path');
const formatXml = require('xml-formatter');
// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false });	
const SAML = require("saml-encoder-decoder-js");
const xmlParser = require("xml2json");
// Nodejs encryption with CTR
const crypto = require('crypto');

// Token signing options
const sOptions = {
	    issuer: "Authorizaxtion/Resource/This server",
	    subject: "iam@user.me", 
	    audience: "Client_Identity" // this should be provided by client
	   }
var signOptions = {
    issuer:  sOptions.issuer,
    subject:  sOptions.subject,
    audience:  sOptions.audience,
    expiresIn:  "30d",    // 30 days validity
    algorithm:  "RS256"    
};

/*
 * ==================== JWT Verify =====================
 */
var verifyOptions = {
issuer:  sOptions.issuer,
subject:  sOptions.subject,
audience:  sOptions.audience,
expiresIn:  "12h",
algorithm:  ["RS256"]
};


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
module.exports = {
		samlGenKeysPEM: function (keysize, prvkeyName, pubkeyName) {

			const {privateKey, publicKey} = 
				crypto.generateKeyPairSync("rsa", {modulusLength: keysize});
			const privateKeyString = privateKey.export({type: "pkcs8", format: "pem"}).toString();
			const publicKeyString = publicKey.export({type: "spki", format: "pem"}).toString();
			fs.writeFile(prvkeyName, privateKeyString, function(err) {
			    if (err) {
			      console.log("err")
			    } else {
			      console.log(prvkeyName + ":  file successfully created.");
			    }
			  });
			fs.writeFile(pubkeyName, publicKeyString, function(err) {
			    if (err) {
			      console.log("err")
			    } else {
			      console.log(pubkeyName + ":  file successfully created");
			    }
			});
		},

		
		
		/**
		 * 
		 * 
		 * 
		 * 
		 * @param firstname
		 * @returns
		 * 
		 */
		jwtSignToken: function (payload, privateKey, sOptions, jwtFile)  {	
			if (sOptions === null) {
				   sOptions = {
				    issuer: "Authorizaxtion/Resource/This server",
				    subject: "iam@user.me", 
				    audience: "Client_Identity" // this should
								// be provided
								// by
												// client
				   }
			}
				 
			  var token = jwt.sign(payload, privateKey, signOptions, jwtFile);
			   fs.writeFile(jwtFile, token, function(err, data) {
				    if (err) {
				      console.log("err")
				    } else {
				      console.log(data + "  jwt signed file successfully created");
				    }
				});
			},
			
			
		
			
			/**
			 * 
			 * 
			 * 
			 * 
			 * @param firstname
			 * @returns
			 * 
			 */
		jwtVerifyToken: function (token, jwtFileName, pubFileName, verifyOptions )	{
			console.log("jwtVerifyToken:  001 : " + pubFileName);
			var pubStr;
			if (verifyOptions === null) {
				verifyOptions = {
					    issuer: "urn:claves.com:idp\\r\\n\\t",
					    subject: "saml.jackson@example.com\\r\\n\\t\\t\\t", 
					    audience: "http://www.prathamesh-phadnis.com:3000/execServ\\r\\n\\t\\t\\t\\t" // this
															    // should
															    // be
															    // provided
															    // by
													// client
					   }
			}

			if (token === null ) {
				console.log("jwtVerifyToken:  002:" + jwtFileName);
				fs.readFile( jwtFileName, function(err, data) {
					console.log("jwtVerifyToken:  003");
					if (err) {
						console.log("error getting   " + jwtFileName + "    file");
					} else {
						// console.log("token: " +
						// data);
						token = data.toString();
						console.log("token:  " + token.toString());
						console.log("pubStr:  " + pubFileName);
						try {
							var legit = jwt.verify(token, pubFileName, null);
							console.log("\nJWT verification result: " + JSON.stringify(legit));
						} catch (e) {						     
						     console.log(e);
						}
					}
				});

			}
		},
		
		
		/**
		 * 
		 * 
		 * 
		 * 
		 * @param firstname
		 * @returns
		 * 
		 */
		jwtCreateJTI: function (length)	 {
			/** Sync */
			  return secureRandom(length).toString();
		}
}


