require('dotenv').config();
const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const path = require('path');
const formidable = require("formidable");
const fileUpload = require('express-fileupload');
var select = require('xml-crypto').xpath
  ,	xpath = require('xpath')
  , dom = require('xmldom').DOMParser
  , SignedXml = require('xml-crypto').SignedXml
  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
  , fs = require('fs')
  , fsPromises = require("fs/promises");
const Users =  require("../models/com.utes.auth.users");
const envsec = require('../secure_envelop/com.utes.secure.env');
const protocolJwt = require('./com.utes.jwt.decoder');
const protocolSaml = require('./com.utes.saml.decoder');
const protocol509 = require('./com.utes.x509.decoder');
const parseCurl = require('./parseCurlData');

var nID = '';

/**
     *
     */
    async function getProtocolTrans(req, res, next) {
        try {
          if (req.method === 'GET' && req.method !== 'POST') {
            console.log('GET');
            req.on('data', function (chunk) {
                  if(debug) {console.log('GET DATA!' + JSON.stringify(data));}
              });
          }				
          if (req.method === 'POST' && req.method !== 'GET') {
            console.log('POST');
            //app.post('/protocoltrans', async function (req,res, next) {
            var convrtObj = '';
            var conv = req.query.convrt;
            //var file = req.query.file;
            console.log("protocoltrans:   executed .."  + conv );
            // command failed due to -X not recognised
            // issue this command: Remove-item alias:curl
            //curl -X POST -H --silent --data-urlencode "payload={\"text\": \"$(cat commands.txt | sed "s/\"/'/g")\"}" http://pratham002.phadnis.no:3000/protocoltrans
            // curl  -H "Content-Type:application/octet-stream" --data-binary testfile.txt http://localhost:3000/protocoltrans
            // curl --request POST --data-binary "signedAssert.xml" http://localhost:3000/protocoltrans
            // curl -X POST http://localhost:3000/protocoltrans -H "Content-Type:application/octet-stream" --data-binary file@signedAssert.xml
            // curl -X POST http://localhost:3000/protocoltrans -d "<Request><Login>my_login</Login><Password>my_password</Password></Request>"
            // curl http://localhost:3000/protocoltrans  -d $file=testXml.xml -H "Content-Type: application/xml"
            // curl -F file=@karan123456_x5jwtok.jwt http://localhost:3000/protocoltrans (working)
            // curl -F file=@testXml.xml http://localhost:3000/protocoltrans
            // curl -v -H "Content-Type: application/xml" POST -d $file=testXml.xml http://localhost:3000/protocoltrans
            // curl -F file=@samlResponse1.xml http://localhost:3000/protocoltrans?convrt=saml-oauth
            // curl -F file=@ajeetphadnis_signedAssert.xml http://localhost:3000/protocoltrans?convrt=saml-oauth
            // curl -F file=@samlRandomResponse.xml http://localhost:3000/protocoltrans?convrt=saml-oauth
            // curl -s -o response.txt -w "%{http_code}" -F file=@samlTest2_signedAssertion.xml --header 'Accept: application/json' http://localhost:3000/protocoltrans?convrt=saml-x509
            // curl -s -o response.txt -w "%{http_code}" -F file=@samlTest2_signedAssertion.xml --header 'Accept: application/json' http://localhost:3000/protocoltrans?convrt=saml-x509
            // curl -F file=@HydroASA_DOMAINCert.pem  http://localhost:3000/protocoltrans?convrt=x509-oauth
            // curl -F http://localhost:3000/protocoltrans?convrt=saml-oauth&file=protocolservice/samlResponse1.xml
            // curl -F file=@samlTestResponse.xml  http://localhost:3000/protocoltrans?convrt=saml-x509
            // curl -s -o response.txt -w "%{http_code}"  -F file=@saml01@salesforce.com_selfsigned.crt  --header 'Accept: application/json' http://localhost:3000/protocoltrans?convrt=x509-saml
            // curl -F file=@saml2jwt_00DD0000000F7L5.jwt  http://localhost:3000/protocoltrans?convrt=oauth-saml
            // curl -F file=@saml2jwt_00DD0000000F7L5.jwt  http://localhost:3000/protocoltrans?convrt=oauth-x509
            // curl -F file=@samlTest1.xml http://localhost:3000/protocoltrans?convrt=saml-oauth
            // curl -F file=@samlTest2_signedAssertion.xml http://localhost:3000/protocoltrans?convrt=saml-oauth
            // curl -F file=@samlTest3signedMessage.xml http://localhost:3000/protocoltrans?convrt=saml-oauth
            // curl -F file=@samlTest4signedMsgAssrt.xml http://localhost:3000/protocoltrans?convrt=saml-oauth
            // curl -s -o response.txt -w "%{http_code}" -F file=@saml2jwt__ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7.jwt --header 'Accept: application/json'  http://localhost:3000/protocoltrans?convrt=oauth-x509
            // curl -s -o response.txt -w "%{http_code}" -F file=@../protoExchangeTokens/saml2jwt_test.jwt --header 'Accept: application/json'  -X POST -k https://localhost:20443/getProtocolTrans?convrt=oauth-saml
            // Invoke-WebRequest : A parameter cannot be found that matches parameter name 'F'.
            // Remove-item alias:curl
            var body = '';
          // below code for javascript xmlhttprequest client
          // stream data event triggered
          req.on('data', async function(data) {
            data = data.toString('utf8');
            //console.log("dataStart:   " + data);
            // When curl client sends data, it needs special filtering as below
            if (data.startsWith("--------------------------")) {
              data = await parseCurl.processLineByLine(data, conv);
              data = JSON.stringify(data);
              var parsed = JSON.parse(data);
              data = parsed.data;
              //console.log("data:   " + data);
            } else {
              //console.log("data11:   " + data);
              var ncnt = (data.match(/\r\n/g)||[]).length;
              //console.log("data12:   " + ncnt);
              if (ncnt) {
                data.replace(/\r?\n|\r/g, " ");
              //console.log("data1:   " + data);
              }
            }
            // end of curl data filtring
              body = data;
              //console.log("chunk:   " + data);
          });

        // stream end of data event triggered
        // DOMParser will fetch you the xml tag values when traversing dom
              req.on('end', async function () {
                //console.log("chunk:   " + body);
                //console.log("end:   " + body);
                // detect if the stream is xml with '<' as first char.
                // detect if the stream is json with '[' or '{' as first char.
                // detect if the stream is x509 with '-----BEGIN CERTIFICATE-----'  as first line.
                  fs.writeFile('E:/temp/result.xml', body, async function() {
                    var c = Buffer.from(JSON.stringify(body, 'utf8'));
                    var parsed = JSON.parse(c);
                    console.log("body:    " + parsed.trim());
                    // set or call stream processing modules by detecting body type
                    if (conv === "saml-oauth"  && parsed.startsWith("<samlp:Response") ) {
                      // than its xml stream
                      //console.log("saml_resp:  " + parsed);
                      convrtObj = await protocolSaml.idpSamlDecoder(parsed, 'resp', conv);
                      console.log("saml2oauthValue:resp:   " +JSON.stringify(convrtObj));
                      res.end('Successfully Posted' + JSON.stringify(convrtObj));              
                    } else if (conv === "saml-x509"  && parsed.startsWith("<samlp:Response")) {
                      //console.log("saml_x509:  " + parsed);
                      convrtObj = await protocolSaml.idpSamlDecoder(parsed, 'resp', conv);
                      res.end('Successfully Posted' + JSON.stringify(convrtObj));
                    } else if ((conv === "saml-oauth" ) && parsed.startsWith("<saml:Assertion")) {                
                        console.log("saml_assrt:  " + parsed);
                        convrtObj = await protocolSaml.idpSamlDecoder(parsed, 'asrt', conv);
                        nID = protocolSaml.getNid();
                        uid = protocolSaml.getUid();
                        var mail = protocolSaml.getEmail();
                        var sid = '';
                        if (uid) {
                          sid = uid;
                        } else if (mail) {
                          sid = mail;
                        } else {
                          sid = nID;
                        }
                        console.log("saml2oauthValue:asrt:   " + sid);
                        await fsPromises.readFile("./protoExchangeTokens/saml2jwt_" +sid+".jwt", 'utf8').then(function(result) {
                          console.log("FileRead:  "+result);
                          res.end('Successfully Posted:    ' + result);
                        })
                        .catch(function(error) {
                          console.log(error);
                        });
                      } else if (conv === "saml-x509"  && parsed.startsWith("<saml:Assertion")) {
                        //console.log("saml_x509:  " + parsed);
                        convrtObj = await protocolSaml.idpSamlDecoder(parsed, 'asrt', conv);
                        nID = protocolSaml.getNid();
                        console.log("nID:  " + nID);
                        await fsPromises.readFile('./demo_certs/'+nID+'_selfsigned.crt', 'utf8').then(function(result) {
                          console.log("FileRead:  "+result);
                          res.end('Successfully Posted:    ' + result);
                        })
                        .catch(function(error) {
                          console.log(error);
                        });
                        //console.log("saml_x509:::  " + protocol509.certP12Pem);

                      /*var parser = new DOMParser();
                      var xmlDoc = parser.parseFromString(parsed, "text/xml");
                      var tag1 = xmlDoc.getElementsByTagName('to')[0].textContent;
                      console.log("xmlDom:    " + tag1);
                      var content = tag1.toString().replace('\r\n\t', ',');
                      console.log("content:    " + content);*/
                    } else if (parsed.charAt(0) === '[' || parsed.charAt(0) === '{' ) {
                      // than its json stream
                    } else if ((conv === "x509-oauth" || conv === "x509-saml") && parsed.substring(0, 27) === '-----BEGIN CERTIFICATE-----') {
                      // than its a x509 cert stream
                      convrtObj = await protocol509.verifyDecodeX509Cert(parsed, conv);
                      console.log("x509-saml:    " + convrtObj);
                      await res.end('Successfully Posted' + convrtObj);
                    } else {
                      if ((conv === "oauth-saml" || conv === "oauth-x509") && parsed.charAt(0) === 'e') {
                        console.log("jwtStr:    " + parsed);
                        convrtObj = await protocolJwt.parseJwt(parsed, conv);
                        // console.log('Successfully Posted:    ' + convrtObj);
                        await res.end('Successfully Posted' + convrtObj);
                      } else {
                        console.log("The string received is not a valid certificate or token");
                        res.end("The string received is not a valid certificate or token");
                      }
                    }
                  });
                  //  await res.end('Successfully Posted' + convrtObj);
                  });
              };

        // below code for curl client
        /*
          req.on('data', function(data) {
            body += data;
            console.log(data);
        });

        req.on('end', function (){
            fs.writeFile('E:/User/nodejs/nodejs/tasks/result.xml', body, function() {
              console.log(body);
                res.end('Successfully Posted');
            });
        });

        });*/
      } catch (err) {
        console.log(err);
      }
    }


    exports.getProtocolTrans = getProtocolTrans;
