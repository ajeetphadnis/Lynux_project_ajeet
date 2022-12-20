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
JWT 				  	  = require('jsonwebtoken'),
xmlParser1 				  = require('xml2json'),
formatXml 				  = require('xml-formatter'),
bodyParser 				  = require('body-parser');
var buffer 				  = require('buffer/').Buffer;
var stripPrefix 		  	  = require('xml2js').processors.stripPrefix;
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
//bodyParser.urlencoded({ extended: true }); 
var Id;
var Iss;
var sub;
var aud;
var jti;
var nbf;
var iat;
var exp;
var xmlString;
var legit;
global.jwstr;
var uid;


var debug = process.env.DEBUG9;
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
const readFile = (filePath, encoding) => {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, encoding, (err, data) => {
            if (err) {
                return reject(err);
            }
            resolve(data);
            if(debug) {console.log(data.toString('utf8'));}
            return data.toString();
        });
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
async function jwt2IdpSaml(uid, text, req, res, next) {
	req.app.set(bodyParser.urlencoded({ extended: true }));
	
	var pubStr;
	var token = null;
	var filePath = '../phaSAMLNodejsIDP';
	pubStr = await readFile(text+uid+'_selfsigned.crt', );
	var prvStr = await readFile(text+uid+'_prvKey.pem', 'utf8');
	var pub64Str = await buffer.from(pubStr).toString('base64');
	var prv64Str = await buffer.from(prvStr).toString('base64');
	tokStr = await readFile('./samlIdpResp2jwt_rsa_signed.jwt');
	var cert = fs.readFileSync('./server.crt', 'utf8');
//	fs.readFile( './server.crt', function(err, data) {
//		console.log("jwt2IdpSaml:  001");
//		if (err) {
//			console.log("error getting " + filePath + " file");
//		}
//		pubStr = data;
//		console.log("jwt2IdpSaml:  002:   " + pubStr);
//		
//	});
	token = null;
	//jwtVerify.jwtVerifyToken(null, './samlIdpResp2jwt_rsa_signed.jwt', pubStr, null);
	if (token === null ) {
		var date = new Date();
		var validTo = new Date();
		validTo.setHours( validTo.getHours() + 2 );
		// now you can get the string
		var nbef = new Date();
		var notBefore = nbef.toISOString();
		if(debug) {console.log("jwt2IdpSaml003: nbf:  " + notBefore);}
		if(debug) {console.log("jwt2IdpSaml004:   after:  " + validTo.toISOString());}
		
		if(debug) {console.log("jwt2IdpSaml:  005:" + text);}
		//fs.readFile( text, function(err, data) {
		fs.readFile( text+uid+"_saml2jwtRsaSigned.jwt", function(err, data) {
			if(debug) {console.log("jwt2IdpSaml:  006");}
			if (err) {
				console.log("error getting   " + text + "    file");
			} else {
				//console.log("token:  " + data);
				var dt = new Date();
				token = data.toString();
				if(debug) {console.log("jwt2IdpSaml007:   token:  " + token.toString('utf-8'));}
				trmPubStr = pub64Str.toString('utf-8').trim();
				if(debug) {console.log("jwt2IdpSaml008:   trmPubStr:  " + trmPubStr);}
				try {
					legit = JWT.verify(token, cert.toString('utf-8'), {algorithms: ['RS256']});
					//legit = await JWT.verify(token.split(" ")[1].toString(),pubStr);
					req.body.result = legit;
					if(debug) {console.log("jwt2IdpSaml009:   JWT verification result: " + JSON.stringify(legit));}
					global.jwstr = JSON.stringify(legit);
					//Id = legit.id;
					Id = uid;
					Iss = legit.iss;
					sub = legit.sub;
					aud = legit.aud;
					jti = legit.jti;
					nbf = notBefore; //legit.nbf;
					iat = validTo.toISOString(); //legit.iat;
					exp = validTo.toISOString(); //legit.exp;
				} catch (e) {						     
				     console.log(e);
				}
			}

	
		if(debug) {console.log("jwt2IdpSaml010:  " + process.env.SAML_SRV);}
		//const crSamlResp = fs.readFileSync(filePath+"saml_resp.xml", "utf-8");
		fs.readFile(process.env.SAML_SRV+"/saml_resp.xml", "utf-8", function (error, text) {
			if (error) {
				console.log("xml file read error:    " + error);
			} else {
				var parser = new DOMParser();
				var document = parser.parseFromString(text, 'text/xml');
					document.getElementsByTagName('saml:Issuer')[0].textContent = Iss;
					document.getElementsByTagName('saml:NameID')[0].textContent = Id;
					//result["samlp:Response"]["saml:Issuer"].$t = Iss;
					document.getElementsByTagName('saml:Audience')[0].textContent = aud;
					document.getElementsByTagName('saml:Subject')[0].textContent = sub;
					document.getElementsByTagName('saml:Conditions')[0].setAttribute("NotBefore" ,nbf);
					document.getElementsByTagName('saml:Conditions')[0].setAttribute("NotOnOrAfter", iat);
					document.getElementsByTagName('saml:AuthnStatement')[0].setAttribute("AuthnInstant",  iat);
					document.getElementsByTagName('samlp:Response')[0].setAttribute("ID", jti);
					document.getElementsByTagName('samlp:Response')[0].setAttribute("IssueInstant", iat);		
					//document.getElementsByTagName('saml:Issuer')[0].setAttribute("xmlns:saml", "urn:phadnis:names:tc:SAML:2.0:assertion");
					//SERIALIZE TO STRING
					//console.log("DOM Attr  :  " + document.getElementsByTagName('saml:Issuer')[0].getAttributeNode('xmlns:saml').nodeValue);
				    xmlString = new XMLSerializer().serializeToString(document);
				    fs.writeFile("./data.xml", xmlString, function(err, xmlString) {
				        if (err) {
				          console.log("err")
				        } else {
				          console.log("Xml file successfully updated.");
				          console.log("LIGIT:  " + JSON.stringify(legit))
				          //return JSON.stringify(legit);
				        }
				      });
				    return JSON.stringify(legit);
				}
		    return JSON.stringify(legit);
		});
	  });
	}
}

exports.jwt2IdpSaml = jwt2IdpSaml;
