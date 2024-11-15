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

const jwt2cert = require('../jwks/com.utes.jwt.cert');
const fs = require('fs');
const args = process.argv.slice(2);
//var jwk = fs.readFileSync(args[0]);
var pubkey;
var pem;
var pubStr;

var debug = process.env.DEBUG11;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
}

var DUMP_PRIVATE_KEY = ('true' == args[1]);


	/**
	 * jwtks2pem:  
	 * @param id
	 * @param text
	 * @param newuser
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	function jwtks2pem(id, text, newuser, req, res, next) {
		/*var jwk = {
		            "kty": "RSA",
		            "kid": "user1",
		            "x5t": "Z2yJeGKnXIW8eyD7fU60MAsjKL8",
		            "n": "qV-fGqTo8r6L52sIJpt44bxLkODaF0_wvIL_eYYDL55H-Ap-b1q4pd4YyZb7pARor_1mob6sMRnnAr5htmO1XucmKBEiNY-12zza0q9smjLm3-eNqq-8PgsEqBz4lU1YIBeQzsCR0NTa3J3OHfr-bADVystQeonSPoRLqSoO78oAtonQWLX1MUfS9778-ECcxlM21-JaUjqMD0nQR6wl8L6oWGcR7PjcjPQAyuS_ASTy7MO0SqunpkGzj_H7uFbK9Np_dLIOr9ZqrkCSdioA_PgDyk36E8ayuMnN1HDy4ak_Q7yEX4R_C75T0JxuuYio06hugwyREgOQNID-DVUoLw",
		            "e": "AQAB"
		        },*/		
			var jwkVal = fs.readFileSync(text);
			//var jwtStr = jwtParse.createJWK2PEM(jwkVal, id);
			var jwtStr = jwt2cert.parseJwtCrPem(jwkVal, id, newuser);
			
			if(debug) {console.log("jwk2Pem file:  " + JSON.stringify(jwtStr));}
			return JSON.stringify(jwtStr);

	};
exports.jwtks2pem = jwtks2pem;
exports.pem = pem;