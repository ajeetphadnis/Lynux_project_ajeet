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
const fsPromises = require("fs/promises");

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

var uid = '';
var email = '';
var edu1 = '';
var edu2 = '';
var edu = '';
var x509Cert = '';
var subConfData_NOOA = '';
var subConfData_recpnt = '';
var subConfData_inresp = '';
var issuer = '';

jwtUser = {
    uid: '',
    mail: '',
    eduPersonAffiliation: ''
}

var x509Str = '';
var nID = '';

function getUid() {
    if (uid) {
        return uid;
    } else {
        return '';
    }
}

function getNid() {
    if (nID) {
        return nID;
    } else {
        return '';
    }
}

function getEmail() {
    if(email) {
        return email;
    } else {
        return '';
    }
}

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
    var samlt = '';
    //console.log("idpSamlDecoder001:  " + mode + "     token:   " + token);
    parseString(token, options, async function (err, result) {
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
        // refer to mapping doc: demo_docs/sstc-saml2-profiles-deploy-x509-cd-02.pdf
        if(type === 'resp' ) {
            nID = result.Response.Assertion.Subject.NameID;
            nID = JSON.stringify(nID._).replace(/["']/g, "");
            console.log(" nID:  " + nID);
            if (result.Response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData) {
                subConfData_NOOA = result.Response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData['$'].NotOnOrAfter;
                subConfData_recpnt = result.Response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData['$'].Recipient;
                subConfData_inresp = result.Response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData['$'].InResponseTo;
            }
            if (result.Response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.KeyInfo) {
                if (result.Response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.KeyInfo.X509Data) {
                    if (result.Response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.KeyInfo.X509Data.X509Certificate) {
                        x509Cert = result.Response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.KeyInfo.X509Data.X509Certificate;
                    }
                }
            }
            issuer = result.Response.Issuer;
            var nbfv = result.Response.Assertion.Conditions['$'].NotBefore;
            //nvfv = new Date(nbfv);
            var nafv = result.Response.Assertion.Conditions['$'].NotOnOrAfter;
            //nafv = new Date(nafv);
            samlt = nbfv+'*'+nafv;
            console.log("idpSamlDecoder003:   " + nbfv + "   nafv:  " + nafv);
            var auds = result.Response.Assertion.Conditions.AudienceRestriction.Audience;
            console.log("idpSamlDecoder004:   " + auds);
            //var nbfv = result.Response.Assertion.Conditions.NotBefore;
            if (result.Response.Assertion.AttributeStatement.Attribute[0]) {
                uid = result.Response.Assertion.AttributeStatement.Attribute[0].AttributeValue;
                uid = JSON.stringify(uid._).replace(/["']/g, "");
                console.log("idpSamlDecoder005:   " +uid);
            }
            if (result.Response.Assertion.AttributeStatement.Attribute[1]) {
                var mail = result.Response.Assertion.AttributeStatement.Attribute[1]['$'].Name;
                //subname = JSON.stringify(subname._).replace(/["']/g, "");
                console.log("idpSamlDecoder006:   " + mail);
            }
            if (result.Response.Assertion.AttributeStatement.Attribute[1]) {
                email = result.Response.Assertion.AttributeStatement.Attribute[1].AttributeValue;
                email = JSON.stringify(email._).replace(/["']/g, "");
                console.log("idpSamlDecoder007:   " + email);
            }
            if (result.Response.Assertion.AttributeStatement.Attribute[2]) {
                edu1 = result.Response.Assertion.AttributeStatement.Attribute[2].AttributeValue[0];
                edu1 = JSON.stringify(edu1); //.replace(/["']/g, "");
                if(result.Response.Assertion.AttributeStatement.Attribute[2].AttributeValue[1]) {
                    edu2 = result.Response.Assertion.AttributeStatement.Attribute[2].AttributeValue[1];
                    edu2 = JSON.stringify(edu2);  //.replace(/["']/g, "");
                }
            }
            //var sigref = result.Response.Assertion.Signature[0].SignedInfo[0].Reference[0];
            //var sig = result.Response.Assertion.Signature[0].SignedInfo[0].Reference[0]['$'].URI;
            console.log("idpSamlDecoder008:  " + issuer);
        } else if (type === 'asrt') {
            nID = result.Assertion.Subject.NameID;
            nID = JSON.stringify(nID._).replace(/["']/g, "");
            console.log(" idpSamlDecoder009:nID:  " + nID);
            var issuer = result.Assertion.Issuer;
            var nbfv = result.Assertion.Conditions['$'].NotBefore;
            //nvfv = new Date(nbfv);
            var nafv = result.Assertion.Conditions['$'].NotOnOrAfter;
            //nafv = new Date(nafv);
            samlt = nbfv+'*'+nafv;
            if (result.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData['$']) {
                subConfData_NOOA = result.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData['$'].NotOnOrAfter;
                subConfData_recpnt = result.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData['$'].Recipient;
                subConfData_inresp = result.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData['$'].InResponseTo;
            }
             if (result.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.KeyInfo) {
                if (result.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.KeyInfo.X509Data) {
                    if (result.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.KeyInfo.X509Data.X509Certificate) {
                        x509Cert = result.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.KeyInfo.X509Data.X509Certificate;
                        console.log("idpSamlDecoder009a:   " + x509Cert);
                    }
                }
            }
            if(result.Assertion.Conditions.AudienceRestriction) {
                if (result.Assertion.Conditions.AudienceRestriction.Audience) {
                    var auds = result.Assertion.Conditions.AudienceRestriction.Audience;
                    console.log("idpSamlDecoder009:  " + JSON.stringify(auds));
                }
            }
            var nbfv = result.Assertion.Conditions['$'].NotBefore;
            if (result.Assertion.AttributeStatement.Attribute[0]) {
                uid = result.Assertion.AttributeStatement.Attribute[0].AttributeValue;
                uid = JSON.stringify(uid._).replace(/["']/g, "");
                console.log("idpSamlDecoder0010:   " +uid);
            }
            if (result.Assertion.AttributeStatement.Attribute[1]) {
                var mail = result.Assertion.AttributeStatement.Attribute[1]['$'].Name;
                //subname = JSON.stringify(subname._).replace(/["']/g, "");
                if (uid === '' || uid === 'undefined' || uid === null) {
                    var mailc = mail.split('@');
                    uid = mailc[0];
                }
                console.log("idpSamlDecoder0011:   " + mail);
            }
            if (result.Assertion.AttributeStatement.Attribute[1]) {
                email = result.Assertion.AttributeStatement.Attribute[1].AttributeValue;
                email = JSON.stringify(email._).replace(/["']/g, "");
                console.log("idpSamlDecoder012:   " + email);
            }
            if (result.Assertion.AttributeStatement.Attribute[2]) {
                edu1 = result.Assertion.AttributeStatement.Attribute[2].AttributeValue[0];
                if (edu1) {
                    edu1 = JSON.stringify(edu1._).replace(/["']/g, "");
                }
                if(result.Assertion.AttributeStatement.Attribute[2].AttributeValue[1]) {
                    edu2 = result.Assertion.AttributeStatement.Attribute[2].AttributeValue[1];
                    edu2 = JSON.stringify(edu2._).replace(/["']/g, "");
                }
            }
            if (result.Assertion.Signature.SignedInfo) {
                var sigref = result.Assertion.Signature.SignedInfo.Reference;
                var sig = result.Assertion.Signature.SignedInfo.Reference['$'].URI; 
                console.log("idpSamlDecoder0014:  " + JSON.stringify(sigref));
            }
        } 
        if (mode === 'saml-oauth') {
             console.log("saml-oauth_decoder");
            const date2 = new Date();
            if(debug) {console.log("xml Parser6:  " + date2 );}
            date2.setHours(date2.getHours()-10);
            if(debug) {console.log("xml Parser6:  " + date2.toISOString());}
            var seconds = date2.getTime() / 1000; // 1440516958
            nbSecs = seconds;
            //seconds = seconds+36000;
            if(debug) {console.log("xml Parser6:  " + date + "       " + seconds);}
            var jtiStr = jwtId.jwtCreateJTI(10);
            jtiStr = jtiStr.replace(/,/g, '-');
            console.log("xml Parser7:  " + jtiStr);
            const date = new Date(nbfv);
            const nbfvs = Math.floor(date.getTime() / 1000);
            const date1 = new Date(nafv);
            const nafvs = Math.floor(date1.getTime() / 1000);
            jwtUser.uid = uid;
            jwtUser.mail = email;
            jwtUser.eduPersonAffiliation = edu1+','+edu2;
            console.log("idpSamlDecoder0013:  " + jwtUser);

            encodedToken = JWT.sign({id: nID, iss: issuer, sub: nID, aud: auds, jti: jtiStr, exp: nafvs, nbf: nbfvs, iat: nbSecs, Principal: jwtUser}, null, { algorithm: 'none'});
            fs.writeFile("./protoExchangeTokens/saml2jwt_" +uid+".jwt", encodedToken, function(err) {
                  if(err) {
                      return console.log(err);
                  }
              }); 
              console.log("result:  " + encodedToken);
            return encodedToken;
        } else if (mode === 'saml-x509') {
            console.log("convert saml to x509");
            var newuser = new Users();
		    if(debug) {console.log("UID:   " + req.body.demoname);}
			newuser.nameIdentifier = nID; //uid+':'+nID;
			newuser.emailAddress = JSON.stringify(auds);
			newuser.fullname =  uid;
			newuser.commonName = nID;
			newuser.orgName = subConfData_recpnt;
            newuser.emailAddress = email;
			newuser.password = uid;
			newuser.mobilePhone = '0078563412';
			newuser.groups = "demo";
            samlt = samlt+'*'+mode+'*'+issuer;
            x509Str = await demoCert.createDemoSelfSignedCert(newuser.nameIdentifier, samlt, newuser, newuser.password, '', '', '');
            //console.log("convert saml to x509 finished:   " + x509Str);
            //return(Promise.resolve(x509Str));
            //return result;
        }
        //return(Promise.resolve(x509Str));
    });
    //return ("convert saml to oauth");
    //return(Promise.resolve(x509Str));
}


exports.idpSamlDecoder = idpSamlDecoder;
exports.encodedToken = encodedToken;
exports.x509Str = x509Str;
exports.getUid = getUid;
exports.getNid = getNid;
exports.getEmail = getEmail;
