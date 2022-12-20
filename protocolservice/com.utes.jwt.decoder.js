/*
 *Module: 
 *Doc:  https://riptutorial.com/jwt/example/20822/what-to-store-in-a-jwt
 *      https://betterprogramming.pub/jwt-ultimate-how-to-guide-with-best-practices-in-javascript-f7ba4c48dfbd
 * examples: "context": {
        "user": {
            "key": "joe",
            "displayName": "Joe Smith"
        },
        "roles":["admin","finaluser"]
    }
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
var stripPrefix 		  = require('xml2js').processors.stripPrefix;
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
//bodyParser.urlencoded({ extended: true }); 
const Users =  require("../models/com.utes.auth.users");
const demoCert = require('../x509_utils/com.utes.security.createDemoSelfSignedCert');
var crAssert = require('../saml_assert/com.utes.assert.samlAssertCreate');

var debug = process.env.DEBUG10;
 if (debug === 'true') {
     debug = 'true';
 } else {
     debug = null;
 }

 var samlt = '';

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

var pemcert = '';




async function parseJwt(token, mode) {
    try {
        console.log("parseJwt001:   " + token);
        // Get Token Header
        const base64HeaderUrl = token.split('.')[0];
        console.log("parseJwt002:   " + base64HeaderUrl);
        const base64Header = base64HeaderUrl.replace(/-/g, '+').replace(/_/g, '/');
        console.log("parseJwt003:   " + base64Header);
        //const headerData = JSON.parse(atob(base64Header));
        //console.log("parseJwt004:   " + JSON.stringify(headerData));
        // Get Token payload and date's
        var header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());
        var payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
        console.log("parseJwt004:  " + JSON.stringify(header) + "     " + JSON.stringify(payload));
        // Convert as directed in mode
        if (mode === 'oauth-saml') {
            console.log("convert jwt to saml");
            // ****************************
            uid = payload.id;
            newuser.nameIdentifier = payload.id;
            console.log("DecodeJWT001:  "+ payload.id  );
			newuser.emailAddress = payload.Principal.mail;
            var mailc = newuser.emailAddress.split('@');
            console.log("DDecodeJWT002:  "+ payload.Principal.mail);
			newuser.fullname = mailc[0];
			newuser.commonName = mailc[1];
			newuser.orgName = mailc[1];
			newuser.password = mailc[0];
			newuser.mobilePhone = '';
			newuser.groups = 'user, admin';
            var iser = payload.iss;
            samlt = payload.exp+'*'+payload.nbf+'*'+'*'+mode+'*'+iser;
            console.log("DDecodeJWT003:  "+ samlt);
            //******************** */
            crAssert.options.cert = fs.readFileSync('SamlAssertCert.pem');
            console.log("DecodeX509Cert006:  "+ mode );
            crAssert.options.key = fs.readFileSync('SamlAssertKey.pem');
            //crAssert.options.issuer = 'idp.utes.com';
            crAssert.options.issuer = iser;
            crAssert.options.lifetimeInSeconds =  '10800';
            //crAssert.options.Conditions = 'https://utes.com/saml';
            crAssert.options.audiences = mailc;
            //crAssert.options.NotBefore = "2021-04-23T23:51:43.745Z";
            //crAssert.options.NotOnOrAfter = "2021-04-23T23:51:43.745Z";
            crAssert.options.recipient = mailc[1]; //attrs_issuer[0].value;
            crAssert.options.inResponseTo = iser; //'https://utes.com/saml/inresponseto';
            crAssert.options.includeAttributeNameFormat = true;
            crAssert.options.emailAddress = newuser.emailAddress;
            crAssert.options.nameIdentifier = uid;
            crAssert.options.sessionIndex = 'jskjflksjeouotui4548958';
            crAssert.options.authnContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
            console.log("DecodeX509Cert007:  "+ mode );
            crAssert.options.attributes = {
                //'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailAddress': newuser.emailAddress,
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': newuser.emailAddress,
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstName': newuser.emailAddress,
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/lastName': newuser.emailAddress,
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayName': newuser.emailAddress,
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilePhone': newuser.mobilePhone,
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups': 'user, developer'
            }
            //console.log("DecodeX509Cert008:  "+ JSON.stringify(crAssert.options) );
            var samlAss = await crAssert.createSamlAssert(newuser.nameIdentifier, crAssert.options, '', '', '');
            console.log("convert x509 to saml finished !!! " + samlAss);
            return samlAss;
        } else if (mode === 'oauth-x509') {
            newuser.nameIdentifier = payload.id;
            console.log("DecodeJWT001:  "+ payload.id  );
			newuser.emailAddress = payload.Principal.mail;
            var mailc = newuser.emailAddress.split('@');
            console.log("DDecodeJWT002:  "+ payload.Principal.mail);
			newuser.fullname = mailc[0];
			newuser.commonName = mailc[1];
			newuser.orgName = mailc[1];
			newuser.password = mailc[0];
			newuser.mobilePhone = '';
			newuser.groups = 'user, admin';
            var iser = payload.iss;
            samlt = payload.exp+'*'+payload.nbf+'*'+'*'+mode+'*'+iser;
            console.log("DDecodeJWT003:  "+ samlt);
            pemcert = await demoCert.createDemoSelfSignedCert(mailc[0], samlt, newuser, newuser.password, '', '', '');            
            //console.log("convert jwt to x509 finished !!    " + pemcert);
            return pemcert;
        }
        //return dataJWT;
    } catch (err) {
        return false;
    }
}

exports.parseJwt = parseJwt;
exports.pemcert = pemcert;
/*const jwtDecoded = parseJwt('eyJ4NWMiOiJNSUlEOXpDQ0F0K2dBd0lCQWdJQkFUQU5CZ2txaGtpRzl3MEJBUVVGQURCMk1SUXdFZ1lEVlFRREV3dHJZWEpoYmpFeU16UTFOakVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnVENGWnBjbWRwYm1saE1STXdFUVlEVlFRSEV3cENiR0ZqYTNOaWRYSm5NUk13RVFZRFZRUUtFd3BRYUdGa2JtbHpTVzVqTVJRd0VnWURWUVFMRXd0cllYSmhiakV5TXpRMU5qQWVGdzB5TVRBMk1ESXhNekUwTlRCYUZ3MHlNakEyTURJeE16RTBOVEJhTUhZeEZEQVNCZ05WQkFNVEMydGhjbUZ1TVRJek5EVTJNUXN3Q1FZRFZRUUdFd0pWVXpFUk1BOEdBMVVFQ0JNSVZtbHlaMmx1YVdFeEV6QVJCZ05WQkFjVENrSnNZV05yYzJKMWNtY3hFekFSQmdOVkJBb1RDbEJvWVdSdWFYTkpibU14RkRBU0JnTlZCQXNUQzJ0aGNtRnVNVEl6TkRVMk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBNFhzNmtHQkpid1JzaWl2eXpzdVNWa2JFYmNFNlRqR3ZXQlE4Q3ZWbW96SlNvTTlGUHM0TVNTenBJQUFtNUU5MUZuT3JkUjVjekJrQ2hsRElIeDk5SXJZZmVCUTdpaDBVOXRmQ3FTTm55dUxsU3RVVE1FSlh3V0E1SzltNWt6NFA1encxSFpESDB4cTU1dVloQ1dFTWtUa0NKM0xMZXA5SWdUNngrZmdWTFkwVHByV3J4NFlKeHpDTWhQQzJ0RjdOZmw1dXV4NEZWaHFrZjMvaGR4VFVPdVF4d1JRNEpndXNkbmtsRGs2SktOQlVOSnpNa1Vsdi9tOW9FZmNSUnR0YjJ1Y3NTOXhBQ2Y1ZGlqQ3A4S2o5MG1qbUkvYWd1N0ZUTGhHT2pkczVUaTIrbW1PRXkra1JXUWVTQnlGT3VVcVBwRlI1U3M2WnQzZk5JWU5jZG9hTHpRSURBUUFCbzRHUE1JR01NQXdHQTFVZEV3UUZNQU1CQWY4d0N3WURWUjBQQkFRREFnTDBNRHNHQTFVZEpRUTBNRElHQ0NzR0FRVUZCd01CQmdnckJnRUZCUWNEQWdZSUt3WUJCUVVIQXdNR0NDc0dBUVVGQndNRUJnZ3JCZ0VGQlFjRENEQXlCZ05WSFJFRUt6QXBoaWRvZEhSd2N6b3ZMM2QzZHk1d2NtRjBhR0Z0WlhOb0xYQm9ZV1J1YVhNdVkyOXRPalEwTkM4d0RRWUpLb1pJaHZjTkFRRUZCUUFEZ2dFQkFCRXhZajJ0d1V0YmpTVXBuQnRhcklUOWFRWHU2SWNWMGJ6Ym9FcWtyelZob1UxYjFZZWtmMUNoay9WdS9YYXR0L203aTlWaTFkbklpM2d2LzdtbHVpWU8vSFZMRkpTYmErQWxpeVJlUjVHUVhKcXBtQ28vUExHMDdENHZuTnBjY09nL2RrUjZFSm84bVJCd3JabGlPZkd1UlJqaVh1dUUyWEFDemVBUnpnV2MrYStDcXU4WlJkQVQvSXc5R0ZOWm1HNHJRVkxQVTZFT0NMbTNrNXNXYmY0ZEt3N28ycUJCNEZxVXNack9qaEp0Y1NJNStYRXJlSmsxRnJNbXJmK09sT0V5ajlDNVZCRjAwWlVBK2JsVUh6UVVQcW1zVkU3VEpQU2pjcWRPTk1MSFI3dUZiSmNvQXhSSnB2OWlJdmExR0xSeVBoRDRpb3pGQ2dsMmtRY0diVXc9IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJpZHAudXRlcy5jb20iLCJzdWIiOiJrYXJhbjEyMzQ1NiIsImF1ZCI6Imh0dHBzOi8vdXRlcy5jb20vc2FtbCIsIm5iZiI6MTYyMjY3NTY5MCwiaWF0IjoxNjU0MjExNjkwLCJleHAiOjE2NTQyMTE2OTB9.ZMCzyBfTIdEGR5l6ym-6Pk4i-GrDE4fXySWjUpDIb9tbP5xRttKQ_Bd6LXkXil9cF5pJI1PInbXJ62_uMmS3pDW3CIOPhoNf5npBKNeMkPNh2A_Gop3ba_zIMsF-GUcjTV-UenZ5VHngFTKJQz4hbk4OgR8QQrwroeVmhgvMN7H3tnyApaXiqo3iOzRolyoJcn4OMOLr6PfMtG9xNWO2OhOxxhAGXdYpsAX7pfnZ0dgpX8eD1ngBFBGT1Ew9a9M2MGp5LSrZa4TTYf3btxucU6GJQn8Ah2u9YMOiXAQ2Qf1RLG8AtG0c9dMpkzQGFDdzdyuCBDzDcn8WaY8qDTICBg');
if (jwtDecoded) {
    console.log(jwtDecoded);
}*/