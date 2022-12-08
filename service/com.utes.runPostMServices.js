/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * https://stormpath.com/blog/beginners-guide-jwts-in-java
 * 
 * https://www.jsonwebtoken.io/
 */
require('dotenv').config();


const express=require('express');
const expr=express();
// const router = express.Router();
const bodyParser = require('body-parser');
var request = require('request');
//var nJwt = require('njwt');
var secureRandom = require('secure-random');
var fs = require('fs');
const path = require('path');
var parseString = require("xml2js").parseString;


const jwtks2pem = require('./com.utes.jwtks-to-pem');
const pem2jwks  = require('./com.utes.pem-to-jwks');
//const saml2json = require('./com.utes.saml-to-json');
const idpsaml2jwt = require('./com.utes.idp.saml2jwt');
const jwt2Idpsaml = require('./com.utes.idp.jwt2saml');


var debug = process.env.DEBUG13;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
}



var postServ = { 
	postMSrv:	function (req, res, next) {
		req.app.set("views", path.join(__dirname))
		req.app.set("view engine", "ejs")

		//create application/x-www-form-urlencoded parser
		var urlencodedParser = bodyParser.urlencoded({ extended: true });
		var fval = req.body.opFile;
		var srvc = req.body.serv;
		var result = req.body.result;
		var emil = req.body.email;
		var nam = req.body.name;
		
		var signingKey = secureRandom(256, { type: 'Buffer' }); // Create a highly random byte array of 256 bytes
		console.log("fval:  " + emil + "    name: " + nam);
		if (srvc === "serv1") {
			let rawdata = fs.readFileSync(fval);
			let jstr1 = JSON.parse(rawdata);
			var pem = jwtks2pem.jwtks2pem(jstr1);
			var result1 = fs.readFile('./jwtkspem.pem', 'utf8' , (err, data) => {
				if (err) {
					console.error(err);
					return;
				}
				res.send(data);
				});
			/*fs.writeFile('javaInit2.js', jstr, function (err, file) {
					if (err) throw err;
					console.log('Saved!');
			});*/
		}
		if (srvc === "serv2") {
			let rawdata = fs.readFileSync(fval);
			//let jstr1 = JSON.parse(rawdata);
			var jwt = pem2jwks.pem2jwks(rawdata);
			var result2 = fs.readFile("./pem2jwtks.json", 'utf8' , (err, data) => {				
				if (err) {
					console.error(err);
					return;
				}
				if(debug) {console.log(data);}
				res.send(data);
				});
		}
		if (srvc === "serv3") {
			var data = saml2json.samlResponseBase64Encoded(fval);
			//console.log(data);
			//res.send(data);
			var result3 = fs.readFile("./samlRespB64ToJson.json", 'utf8' , (err, data) => {				
				if (err) {
					console.error(err);
					return;
				}
				if(debug) {console.log(data);}
				res.send(data);
			});
		}
		if (srvc === "serv11") {
			var uid;
			//req.body.result = "Text area data";
			var ret = idpsaml2jwt.idpSaml2Jwt(uid, fval, req, res, next);
			req.body.result = ret;
			//console.log("serv11:  " + req.body.result);
			//res.send(data);
			var result4 = fs.readFile("./samlIdpResp2jwt_rsa_signed.jwt", 'utf8' , (err, data) => {				
				if (err) {
					console.error(err);
					return;
				}
				//console.log(ret);	
				req.body.result = data.toString().replace(/\{\{result\}\}/, ret);
				    res.writeHead(200);
				    res.end(req.body.result, 'utf8');
				//req.body.result = ret;
				//console.log("Serv11:   " + req.body.result);
				//res.send(ret);

				//req.query.result = ret;
			});
		}
		if (srvc === "serv12") {
			var uid;
			//req.body.result = "Text area data";
			var ret = jwt2Idpsaml.jwt2IdpSaml(uid, fval, req, res, next);
			req.body.result = ret;
			if(debug) {console.log("serv12:  " + req.body.result);}
			//Do Something
			var myHtmlData;
			var msg;
			var email1 = "ajeet.phadnis@dfo.no";
			var samlA;
			var x509Token;
		    fs.readFile('./views/execServiceCommnd.html', (err, data) => {
			    if(err) {
			        throw err;
			    } else {
//		            res.writeHead(200, { 'Content-Type':'text/html'});
			    	msg = JSON.stringify(req.body.result);
		            console.log("messge: " + msg);
		            res.end(JSON.stringify(req.body.result, 'utf8'));
		        } 
			})
		}
	},
};

module.exports = postServ;	
