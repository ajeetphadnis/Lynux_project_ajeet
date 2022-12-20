/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * 
 */
 require('dotenv').config();
 var forge = require('node-forge');
 var fs = require('fs');
 const Users =  require("../models/com.utes.auth.users");
 var crAssert = require('../saml_assert/com.utes.assert.samlAssertCreate');
var saml = require('saml').Saml20; // or Saml11
var XMLSerializer = require('xmldom').XMLSerializer;
const jwtId = require('../jwks/com.utes.jwt_sign_verify');
const JWT = require('jsonwebtoken');

var options = new Object(); 
 var debug = process.env.DEBUG19;
 if (debug === 'true') {
     debug = 'true';
 } else {
     debug = null;
 }
 
 var subjAttrs = [{
    name: 'commonName',
    value: ''
  }, {
    name: 'countryName',
    value: ''
  }, {
    shortName: 'ST',
  }, {
    name: 'localityName',
    value:  ''                    //newuser.orgName
  }, {
    name: 'organizationName',
    value: ''                     //newuser.orgName
  }, {
    shortName: 'OU',
    value:  ''                   //newuser.nameIdentifier
  }];

  var attrs_issuer = [
    {
        name : 'commonName',
        value : ''                 //'com.utes.intermediate_ca-domain'
    },
    {
        name : 'countryName',
        value : ''              //'NO'
    },
    {
        shortName : 'ST',
        value : ''              //'Oslo-Akerhusa'
    },
    {
        name : 'localityName',
        value : ''              //'Oslo'
    },
    {
        name : 'organizationName',
        value : ''              //'UTES_INTERMEDIATE_CA_TRUST_DOMAIN Inc'
    },
    {
        shortName : 'OU',
        value : ''              //'INTERMEDIATE_CA_TRUST_DOMAIN CryptoApps'
    } ];

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

  jwtUser = {
    uid: '',
    mail: '',
    eduPersonAffiliation: ''
}

// Slice and Stitch
function remove_linebreaks_ss( str ) {
    var newstr = "";
      
    for( var i = 0; i < str.length; i++ ) {
        if( !(str[i] == '\r' || str[i] == '\n') ) {
                newstr += str[i];
    }      }
    return newstr;
} 


async function verifyDecodeX509Cert(certStr, mode) {
    try {
        //var certs = certStr.replace(/[\r\n]+/gm, "");
        var certs = remove_linebreaks_ss( certStr );
        console.log("verifyDecodeX509Cert001:  " + certs);
        const crt = forge.pki.certificateFromPem(certs);
        console.log("verifyDecodeX509Cert002:  ");
        if (crt.publicKey.n.toString(2).length < 2048) {
            console.log("verifyDecodeX509Cert003:  ");
         return false;
        }
        var data = crt.subject;
        console.log("verifyDecodeX509Cert Subject1:  " + JSON.stringify(data));
        for (var i=0; i < crt.extensions.length; i++) { 
            if (crt.extensions[i].name === 'subjectAltName') {
                email = JSON.stringify(crt.extensions[i].altNames[1].value);
                console.log("verifyDecodeX509Cert SubjectAltName:   " + email);
            }
         }
        //console.log("verifyDecodeX509Cert Subject2:  " + JSON.stringify(crt.extensions));
        if (data.attributes[0].name === 'commonName') {
            subjAttrs[0].value = (data.attributes[0].value).trim();
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[1].name === 'countryName') {
            subjAttrs[1].value = (data.attributes[1].value).trim();
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[2].name === 'stateOrProvinceName') {
            subjAttrs[2].value = (data.attributes[2].value).trim();
            //console.log(data.attributes[0].name);
            console.log(subjAttrs);
        }
        if (data.attributes[3].name === 'localityName') {
            subjAttrs[3].value = (data.attributes[3].value).trim();
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[4].name === 'organizationName') {
            subjAttrs[4].value = (data.attributes[4].value).trim();
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[5].name === 'organizationalUnitName') {
            subjAttrs[5].value = (data.attributes[5].value).trim();
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        var valid = crt.validity;
        var valid = valid.notBefore+'*'+valid.notAfter;
        console.log(valid);

        var data = crt.issuer;
        if (data.attributes[0].name === 'commonName') {
            attrs_issuer[0].value = data.attributes[0].value;
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[1].name === 'countryName') {
            attrs_issuer[1].value = data.attributes[1].value;
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[2].name === 'stateOrProvinceName') {
            attrs_issuer[2].value = data.attributes[2].value;
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[3].name === 'localityName') {
            attrs_issuer[3].value = data.attributes[3].value;
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[4].name === 'organizationName') {
            attrs_issuer[4].value = data.attributes[4].value;
            //console.log(data.attributes[0].name);
            //console.log(subjAttrs);
        }
        if (data.attributes[5].name === 'organizationalUnitName') {
            attrs_issuer[5].value = data.attributes[5].value;
            //console.log(data.attributes[0].name);
            //console.log(attrs_issuer);
        }
        /*console.log("verifyDecodeX509Cert004a:  " + JSON.stringify(crt.subject));
        console.log("verifyDecodeX509Cert004b:  " + JSON.stringify(crt.validity));
        console.log("verifyDecodeX509Cert004c:  " + JSON.stringify(crt.issuer));
        console.log("verifyDecodeX509Cert004d:  " + JSON.stringify(crt.publicKey));
        console.log("verifyDecodeX509Cert004e:  " + JSON.stringify(crt.serialNumber));*/
        //console.log("verifyDecodeX509Cert004f:  " + JSON.stringify(crt.getCommonName));
        //return /^whistle\.\d+$/.test(getCommonName(crt));
        // Convert as directed in mode
        mode = mode.trim();
        console.log("DecodeX509Cert005:  "+ mode );
        if (mode === 'x509-saml') {
            uid = subjAttrs[0].value;
            console.log("DecodeX509Cert005a:  "+ uid );
            newuser.nameIdentifier = subjAttrs[0].value;
            console.log("DecodeX509Cert005b:  "+ subjAttrs[0].value  );
			newuser.emailAddress = email;
            console.log("DecodeX509Cert005b:  "+ newuser.emailAddress );
			newuser.fullname = subjAttrs[0].value;
			newuser.commonName = subjAttrs[0].value;
			newuser.orgName = subjAttrs[5].value;
			newuser.password = subjAttrs[0].value;
			newuser.mobilePhone = subjAttrs[0].value;
			newuser.groups = subjAttrs[0].value;
            crAssert.options.cert = fs.readFileSync('SamlAssertCert.pem');
            console.log("DecodeX509Cert006:  "+ mode );
            crAssert.options.key = fs.readFileSync('SamlAssertKey.pem');
            //crAssert.options.issuer = 'idp.utes.com';
            crAssert.options.issuer = attrs_issuer[1].value;
            crAssert.options.lifetimeInSeconds =  '10800';
            //crAssert.options.Conditions = 'https://utes.com/saml';
            crAssert.options.audiences = subjAttrs[5].value;
            //crAssert.options.NotBefore = "2021-04-23T23:51:43.745Z";
            //crAssert.options.NotOnOrAfter = "2021-04-23T23:51:43.745Z";
            crAssert.options.recipient = subjAttrs[5].value; //attrs_issuer[0].value;
            crAssert.options.inResponseTo = attrs_issuer[0].value; //'https://utes.com/saml/inresponseto';
            crAssert.options.includeAttributeNameFormat = true;
            crAssert.options.emailAddress = email;
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
        } else if (mode === 'x509-oauth') {
            if (email) {
                var mail = email.split('@');
                uid = mail[1]
            } else {
                uid = subjAttrs[0].value;
            }
            console.log("saml-oauth_decoder:   " + uid);
            const date2 = new Date();
            console.log("xml Parser6:  " + date2 );
            date2.setHours(date2.getHours()-10);
            console.log("xml Parser7:  " + date2.toISOString());
            var seconds = Math.floor(date2.getTime() / 1000); // 1440516958
            var nbSecs = seconds;
            //seconds = seconds+36000;
            console.log("xml Parser8:  " + date2 + "       " + seconds);
            var jtiStr = jwtId.jwtCreateJTI(10);
            jtiStr = jtiStr.replace(/,/g, '-');
            console.log("xml Parser9:  " + jtiStr);
            const nfv = valid.split('*');
            console.log("xml Parser9:  " + nfv[0] + "     " + nfv[1]);
            const date = new Date(nfv[0]);
            const nbfvs = Math.floor(date.getTime() / 1000);
            const date1 = new Date(nfv[1]);
            const nafvs = Math.floor(date1.getTime() / 1000);
            jwtUser.uid = uid;
            jwtUser.mail = email.replace(/\"/g, '');
            jwtUser.eduPersonAffiliation = '';


            encodedToken = JWT.sign({id: subjAttrs[0].value, iss: attrs_issuer[0].value, sub: subjAttrs[0].value, aud: subjAttrs[4].value, jti: jtiStr, exp: nafvs, nbf: nbfvs, iat: nbSecs, Principal: jwtUser}, null, { algorithm: 'none'});
            console.log("xml Parser10:  " + encodedToken);
            fpath = __dirname+'\\..\\protoExchangeTokens\\'
            console.log("xml Parser11:  " + fpath);
            fs.writeFile("./protoExchangeTokens/saml2jwt_"+uid+".jwt", encodedToken, function(err) {
                  if(err) {
                      return console.log(err);
                  }
              }); 
              console.log("result:  " + encodedToken);
            return encodedToken;
        }
       } catch(e) {

       }
       console.log("verifyDecodeX509Cert005:  ");
       return true;
      }


exports.verifyDecodeX509Cert = verifyDecodeX509Cert;