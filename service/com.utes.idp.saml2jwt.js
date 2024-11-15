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
fs 						  = require('fs'),
JWT 				  	  = require('jsonwebtoken'),
stripPrefix 		  	  = require('xml2js').processors.stripPrefix,
bodyParser 				  = require('body-parser');
const jwtId 			  = require('../jwks/com.utes.jwt_sign_verify');



var debug = process.env.DEBUG10;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
}



	/**
	 * idpSaml2Jwt: 
	 * @param uid
	 * @param text
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	function idpSaml2Jwt(uid, text, req, res, next) {
		req.app.set(bodyParser.urlencoded({ extended: true })); 
		var result = req.body.result;
		var filePath = '../phaSAMLNodejsIDP';
		  var parser = new xmlParser.Parser({ explicitArray: false });
		  //const response = fs.readFileSync(filePath+text);
		  const response = fs.readFileSync(text+uid+'_signedAssert.xml');
		  if(debug) {console.log("idpSaml2Jwt001:  " + uid + "      samlStr:   " + response);}
		  parser.parseString(response, function (err, result) {
			  //var nID = result['samlp:Response']['saml:Assertion']['saml:Subject']['saml:NameID'];
			  var nID = result['saml:Assertion']['saml:Subject']['saml:NameID'];
			  nID = JSON.stringify(nID);
			  nID = nID.replace('{"_":"', ''); // $& means
												// the whole
												// matched
												// string;
			  nID = nID.replace(',"$":{"Format":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}}', ''); //
			  nID = nID.substring(0, (nID.length-1));
			  nID = nID.replace(/(\\r\\n|\\n|\\r|\\t)/gm, '');
			  nID = uid;
			  if(debug) {console.log("xml Parser2:  " + nID);}
			  var issu = result['saml:Assertion']['saml:Issuer'];
			  issu = JSON.stringify(issu);
			  issu = issu.replace('{\"_\":\"', '');
			  issu = issu.replace('","$":{"xmlns:saml":"urn:oasis:names:tc:SAML:2.0:assertion"}}', '');
			  issu = issu.replace(/(\\r\\n|\\n|\\r|\\t)/gm, '');
		      if(debug) {console.log("xml Parser3:  " + issu);}
		      var auds = result['saml:Assertion']['saml:Conditions']['saml:AudienceRestriction']['saml:Audience'];
		      auds = JSON.stringify(auds);
		      auds = auds.replace('\"', '');
		      auds = auds.replace('\\"\"', 'v');
		      auds = auds.substring(0, (auds.length-1));
		      auds = auds.replace(/(\\r\\n|\\n|\\r|\\t)/gm, '');
		      // auds =
				// auds.replace('","$":{"xmlns:saml":"urn:oasis:names:tc:SAML:2.0:assertion"}}',
				// '');
		      if(debug) {console.log("xml Parser4:  " + auds);}
			  var sub = result['saml:Assertion']['saml:Subject'];
			  sub = JSON.stringify(sub);
			  sub = sub.replace(/\\r\\n/g, '');
			  sub = sub.replace('{"_":"', ''); // $& means
												// the whole
												// matched
												// string;
			  sub = sub.replace(',"$":{"Format":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}}', ''); //
			  sub = sub.replace(/(\\r\\n|\\n|\\r|\\t)/gm, '');
			  if(debug) {console.log("xml Parser5:  " + sub);}
			  var nbfv = result['saml:Assertion']['saml:Conditions'].$.NotBefore;
	//		  var date = new Date(nbfv);
	//		  var seconds = date.getTime() / 1000; // 1440516958
	//		  nbSecs = seconds;
	//		  seconds = seconds+36000;
	//		  console.log("xml Parser6:  " + nbfv + "       " + seconds);
			  var date = new Date();
			  if(debug) {console.log("xml Parser6:  " + date );}
			  date.setHours(date.getHours()-10);
			  if(debug) {console.log("xml Parser6:  " + date.toISOString());}
			  var seconds = date.getTime() / 1000; // 1440516958
			  nbSecs = seconds;
			  //seconds = seconds+36000;
			  if(debug) {console.log("xml Parser6:  " + date + "       " + seconds);}
			  var jtiStr = jwtId.jwtCreateJTI(10);
			  jtiStr = jtiStr.replace(/,/g, '-');
			  if(debug) {console.log("xml Parser7:  " + jtiStr);}
			  // ec algorithm impl
			  // https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
			  // https://8gwifi.org/ecsignverify.jsp
			  // https://github.com/tinacious/poc-jwt-ecdsa
				// implementation as below.
			  // E:\App2\App2\workspaces\openSAML3\js_jose\poc-jwt-ecdsa-master\poc-jwt-ecdsa-master
			// get private key
			  const privateKey = fs.readFileSync('./ec_private.key');
			  // encode data with the private key using
				// the ES256 algorithm
			  const encodedToken = JWT.sign({id: nID, iss: issu, sub: sub, aud: auds, jti: jtiStr, nbf: nbSecs, iat: seconds}, privateKey, { algorithm: 'ES256', expiresIn: '24h' });
			  fs.writeFile("./samlIdpRes2jwt_ec_signed.jwt", encodedToken, function(err) {
					if(err) {
				        return console.log(err);
				    }
			    });
			  // console.log("EC Token: " + encodedToken);
			  
			  // end ec algorithm impl
			  // key gen site : https://mkjwk.org/
			  // rsa and ec signature:
				// https://github.com/auth0/node-jsonwebtoken/issues/400
			  //var secretKey = fs.readFile('./idp-private-key.pem', 'utf8' , (err, data) => {
			  if(debug) {console.log("xml Parser8:  ");}
			  var secretKey = fs.readFileSync('./server.key');
	//		  , (err, data) => {
	//			  // console.log("pKey: " + data);
	//				if (err) {
	//					console.error(err);
	//					return;
	//				}
					if(debug) {console.log("xml Parser9:  ");}
		            // sign token
		            var token = JWT.sign({id: nID, iss: issu, sub: nID, aud: auds, jti: jtiStr, nbf: seconds, iat: seconds}, secretKey, { algorithm: 'RS256',
		             expiresIn: '24h' });
		            if(debug) {console.log("xml Parser10:  ");}
		            req.body.result = token;
		            if(debug) {console.log("xml Parser11:  ");}
		            //fs.writeFile("./samlIdpResp2jwt_rsa_signed.jwt", token, function(err) {
		            fs.writeFile(text+nID+"_saml2jwtRsaSigned.jwt", token, function(err) {
						if(err) {
					        return console.log(err);
					    }
					    	//req.body.result = token;
						console.log("xml Parser12:  "+ token);
							return token;
				    });
		            //console.log("Token: " + token);
			  });
	
	//  res.render('samlresponse', {
	//    AcsUrl: opts.postUrl,
	//    SAMLResponse: response.toString('base64'),
	//        RelayState: opts.RelayState
	//      });
	}





exports.idpSaml2Jwt = idpSaml2Jwt;




