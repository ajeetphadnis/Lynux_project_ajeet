/**
 * Project: com.utes.saml.decoder
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
const fs = require('fs');
const xmlParser = require('xml2js');
var parseString = require('xml2js').parseString;
var stripNS = require('xml2js').processors.stripPrefix;
//const processors = xmlParser.processors;
const jwtId = require('../jwks/com.utes.jwt_sign_verify');
const demoCert = require('../x509_utils/com.utes.security.createDemoSelfSignedCert');
const Users =  require("../models/com.utes.auth.users");
const JWT = require('jsonwebtoken');

var debug = process.env.DEBUG10;
if (debug === 'true') {
    debug = 'true';
} else {
    debug = null;
}
var encodedToken;

const options = {
    tagNameProcessors: [stripNS],
    explicitArray: false
};



/**
     * idpSaml2Jwt: 
     * @param uid
     * @param text
     * @param req
     * @param res
     * 
     * @param next
     * @returns
     */
async function idpSamlDecoder(token, type, mode) {
/*     if(type === 'resp' ) {
        // for samlp:Response type
        //var token = token.replace(/['"]+/g, '');
        token = token.replace(/(?:\\[rn])+/g, "");
    } else if (type === 'asrt') {
        token = token.replace(/(?:\\[rn])+/g, "");
    } */
    token = token.replace(/(?:\\[rn])+/g, "");
    token = token.replace(/\\/g, "\"");
    //console.log("idpSamlDecoder001:  " + mode + "     token:   " + token);
    parseString(token, options, function (err, result) {
        if (err) {
          // handle error    
          console.log("idpSamlDecoder002:  " + err);
        } 
        // code below work and can extract values with key-value pair
        /*var resultStr = JSON.stringify(result);
        JSON.parse(resultStr, (key, value) => {
            if (typeof value === 'string') {
                if(key === 'uid') user.uid = value;
                    console.log("result: key:  " + key + "  value:  " + value);
              }
            });*/
        // code below get a more direct access to tag name and its value
        // useing this method:
        /* var usr = JSON.stringify(result);
        console.log("JSON_Response:   "  + usr);							          
        JSON.parse(usr, (key, value) => {
            if (typeof value === 'string') {
                console.log("Response: key:  " + key + "  value:  " + value);            
            }
        }); */
        if(type === 'resp' ) {
            var nID = result.Response.Assertion.Subject.NameID;
            nID = JSON.stringify(nID._).replace(/["']/g, "");
            console.log(" nID:  " + nID);
            var issuer = result.Response.Issuer;
            var nbfv = result.Response.Assertion.Conditions['$'].NotBefore;
            console.log("idpSamlDecoder003:   " + nbfv);
            var auds = result.Response.Assertion.Conditions.AudienceRestriction.Audience;
            console.log("idpSamlDecoder004:   " + auds);
            //var nbfv = result.Response.Assertion.Conditions.NotBefore;
            if (result.Response.Assertion.AttributeStatement.Attribute[0]) {
                var uid = result.Response.Assertion.AttributeStatement.Attribute[0].AttributeValue;
                uid = JSON.stringify(uid._).replace(/["']/g, "");
                console.log("idpSamlDecoder005:   " +uid);
            }
            if (result.Response.Assertion.AttributeStatement.Attribute[1]) {
                var subname = result.Response.Assertion.AttributeStatement.Attribute[1]['$'].Name;
                //subname = JSON.stringify(subname._).replace(/["']/g, "");
                console.log("idpSamlDecoder006:   " + subname);
            }
            if (result.Response.Assertion.AttributeStatement.Attribute[1]) {
                var sub = result.Response.Assertion.AttributeStatement.Attribute[1].AttributeValue;
                sub = JSON.stringify(sub._).replace(/["']/g, "");
                console.log("idpSamlDecoder007:   " + sub);
            }
            //var sigref = result.Response.Assertion.Signature[0].SignedInfo[0].Reference[0];
            //var sig = result.Response.Assertion.Signature[0].SignedInfo[0].Reference[0]['$'].URI;
            console.log("idpSamlDecoder008:  " + issuer);
        } else if (type === 'asrt') {
            var nID = result.Assertion.Subject.NameID;
            nID = JSON.stringify(nID._).replace(/["']/g, "");
            console.log(" idpSamlDecoder009:nID:  " + nID);
            var issuer = result.Assertion.Issuer;
            var auds = result.Assertion.Conditions.AudienceRestriction.Audience;
            console.log("idpSamlDecoder009:  " + JSON.stringify(auds));
            var nbfv = result.Assertion.Conditions['$'].NotBefore;
            if (result.Assertion.AttributeStatement.Attribute[0]) {
                var uid = result.Assertion.AttributeStatement.Attribute[0].AttributeValue;
                uid = JSON.stringify(uid._).replace(/["']/g, "");
                console.log("idpSamlDecoder0010:   " +uid);
            }
            if (result.Assertion.AttributeStatement.Attribute[1]) {
                var subname = result.Assertion.AttributeStatement.Attribute[1]['$'].Name;
                //subname = JSON.stringify(subname._).replace(/["']/g, "");
                console.log("idpSamlDecoder0011:   " + subname);
            }
            if (result.Assertion.AttributeStatement.Attribute[1]) {
                var sub = result.Assertion.AttributeStatement.Attribute[1].AttributeValue;
                sub = JSON.stringify(sub._).replace(/["']/g, "");
                console.log("idpSamlDecoder012:   " + sub);
            }
            var sigref = result.Assertion.Signature.SignedInfo.Reference;
            var sig = result.Assertion.Signature.SignedInfo.Reference['$'].URI; 
            console.log("idpSamlDecoder0013:  " + JSON.stringify(sigref));
        } 
        if (mode === 'saml-oauth') {
             console.log("saml-oauth_decoder");
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
            console.log("xml Parser7:  " + jtiStr);
            encodedToken = JWT.sign({id: nID, iss: issuer, sub: sub, aud: auds, jti: jtiStr, nbf: nbSecs, iat: seconds}, null, { algorithm: 'none'});
            fs.writeFile("../protoExchangeTokens/saml2jwt_" +uid+".jwt", encodedToken, function(err) {
                  if(err) {
                      return console.log(err);
                  }
              }); 
              console.log("result:  " + encodedToken);
            return encodedToken;
        } else if (mode === 'saml-x509') {
            if(type === 'resp' ) {
                var nID = result.Response.Assertion.Subject.NameID;
                nID = JSON.stringify(nID._).replace(/["']/g, "");
                console.log("saml-x509 nID:  " + nID);
                var issuer = result.Response.Issuer;
                var nbfv = result.Response.Assertion.Conditions['$'].NotBefore;
                console.log("idpSamlDecoder003saml-x509:   " + nbfv);
                var auds = result.Response.Assertion.Conditions.AudienceRestriction.Audience;
                console.log("idpSamlDecoder004saml-x509:   " + auds);
                //var nbfv = result.Response.Assertion.Conditions.NotBefore;
                if (result.Response.Assertion.AttributeStatement.Attribute[0]) {
                    var uid = result.Response.Assertion.AttributeStatement.Attribute[0].AttributeValue;
                    uid = JSON.stringify(uid._).replace(/["']/g, "");
                    console.log("idpSamlDecoder005saml-x509:   " +uid);
                }
                if (result.Response.Assertion.AttributeStatement.Attribute[1]) {
                    var subname = result.Response.Assertion.AttributeStatement.Attribute[1]['$'].Name;
                    //subname = JSON.stringify(subname._).replace(/["']/g, "");
                    console.log("idpSamlDecoder006saml-x509:   " + subname);
                }
                if (result.Response.Assertion.AttributeStatement.Attribute[1]) {
                    var sub = result.Response.Assertion.AttributeStatement.Attribute[1].AttributeValue;
                    sub = JSON.stringify(sub._).replace(/["']/g, "");
                    console.log("idpSamlDecoder007saml-x509:   " + sub);
                }
                //var sigref = result.Response.Assertion.Signature[0].SignedInfo[0].Reference[0];
                //var sig = result.Response.Assertion.Signature[0].SignedInfo[0].Reference[0]['$'].URI;
                console.log("idpSamlDecoder008saml-x509:  " + issuer);
            } else if (type === 'asrt') {
                var nID = result.Assertion.Subject.NameID;
                nID = JSON.stringify(nID._).replace(/["']/g, "");
                console.log(" idpSamlDecoder009saml-x509:nID:  " + nID);
                var issuer = result.Assertion.Issuer;
                var auds = result.Assertion.Conditions.AudienceRestriction.Audience;
                console.log("idpSamlDecoder009saml-x509:  " + JSON.stringify(auds));
                var nbfv = result.Assertion.Conditions['$'].NotBefore;
                if (result.Assertion.AttributeStatement.Attribute[0]) {
                    var uid = result.Assertion.AttributeStatement.Attribute[0].AttributeValue;
                    uid = JSON.stringify(uid._).replace(/["']/g, "");
                    console.log("idpSamlDecoder0010saml-x509:   " +uid);
                }
                if (result.Assertion.AttributeStatement.Attribute[1]) {
                    var subname = result.Assertion.AttributeStatement.Attribute[1]['$'].Name;
                    //subname = JSON.stringify(subname._).replace(/["']/g, "");
                    console.log("idpSamlDecoder0011saml-x509:   " + subname);
                }
                if (result.Assertion.AttributeStatement.Attribute[1]) {
                    var sub = result.Assertion.AttributeStatement.Attribute[1].AttributeValue;
                    sub = JSON.stringify(sub._).replace(/["']/g, "");
                    console.log("idpSamlDecoder012saml-x509:   " + sub);
                }
                var sigref = result.Assertion.Signature.SignedInfo.Reference;
                var sig = result.Assertion.Signature.SignedInfo.Reference['$'].URI; 
                console.log("idpSamlDecoder0013saml-x509:  " + JSON.stringify(sigref));
            } 
            console.log("convert saml to x509");
            var newuser = new Users();
		    if(debug) {console.log("UID:   " + req.body.demoname);}
			newuser.nameIdentifier = uid;
			newuser.emailAddress = JSON.stringify(auds);
			newuser.fullname =  sub;
			newuser.commonName = sub;
			newuser.orgName = sub;
			newuser.password = uid;
			newuser.mobilePhone = '0078563412';
			newuser.groups = "demo";
            demoCert.createDemoSelfSignedCert(newuser.nameIdentifier, '', newuser, newuser.password, '', '', '');
        }
    });
    return ("convert saml to oauth");
}


exports.idpSamlDecoder = idpSamlDecoder;
exports.encodedToken = encodedToken;
