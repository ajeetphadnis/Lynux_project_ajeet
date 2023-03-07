/**
 *  Module: com.utes.protocol.exchange_server
 */
 const formidable = require("formidable");
 var DOMParser = require('xmldom').DOMParser;
 const path = require('path');
 const fs = require('fs');
 const fsPromises = require("fs/promises");
const express = require('express');
const bodyParser = require('body-parser');
var xmlparser = require('express-xml-bodyparser');
const xml2js = require('xml2js');
const Transform = require('stream').Transform;
const util = require('util');
const cookieParser = require("cookie-parser");
const sessions = require('express-session');
const multiparty = require("multiparty");
const envsec = require('../secure_envelop/com.utes.secure.env');
const protocolJwt = require('./com.utes.jwt.decoder');
const protocolSaml = require('./com.utes.saml.decoder');
const protocol509 = require('./com.utes.x509.decoder');
const parseCurl = require('./parseCurlData');
const app = express();
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');app.use(express.static(path.join(__dirname, '/public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(xmlparser());
var qs = require('querystring');
// creating 24 hours from milliseconds
const oneDay = 1000 * 60 * 60 * 24;
var session;
var conf;
var result;
//session middleware
app.use(sessions({
    secret: "7654321000",
    saveUninitialized:true,
    cookie: { maxAge: oneDay },
    resave: false
}));
// cookie parser middleware
app.use(cookieParser());

var user = {
	uid: '',
	pass: '',
	serv: '',
	srctxt: '',
	destxt: '',
	jwksets: '',
	oprf: '',
	oprt: '',
	Timestamp: '',
	target: '',
	filetype: '',
	Content: '',
	secenv: '',
	keyInfo: '',
	newuser: {}
};

var getRawBody = require('raw-body');
app.use(function (req, res, next) {
    if (req.headers['content-type'] === 'application/octet-stream') {
        getRawBody(req, {
            length: req.headers['content-length'],
            encoding: req.charset
        }, function (err, string) {
            if (err)
                return next(err);

            req.body = string;
            next();
         })
    }
    else {
        next();
    }
  });

  // START: line remove functions

  // Transform sctreamer to remove first line
  /**
   * Function:  RemoveFirstLine
   * @param {*} args 
   * @returns 
   */
  function RemoveFirstLine(args) {
      if (! (this instanceof RemoveFirstLine)) {
          return new RemoveFirstLine(args);
      }
      Transform.call(this, args);
      this._buff = '';
      this._removed = false;
  }
  util.inherits(RemoveFirstLine, Transform);

  RemoveFirstLine.prototype._transform = function(chunk, encoding, done) {
      if (this._removed) { // if already removed
          this.push(chunk); // just push through buffer
      } else {
          // collect string into buffer
          this._buff += chunk.toString();

          // check if string has newline symbol
          if (this._buff.indexOf('\n') !== -1) {
              // push to stream skipping first line
              this.push(this._buff.slice(this._buff.indexOf('\n') + 2));
              // clear string buffer
              this._buff = null;
              // mark as removed
              this._removed = true;
          }
      }
      done();
  };




  // END: line remove functions

 //ROUTES

 app.get('/secenv',function(req,res){
    console.log("Get:");
    session=req.session;
    session.uname = 'ajeet';
    session.user = user;
     res.sendFile(path.join(__dirname,  'views/com.utes.protocol.exchange.html'));
 });


 app.get('/protocoltrans',function(req,res){
  console.log("Get:");
  session=req.session;
  session.uname = 'ajeet';
  session.user = user;
  return res.send('Received a GET HTTP method');
});


 app.post('/secenv', async function (req,res, next) {
    const uploadFolder =  "./uploads";
    console.log("POSTFunc:uploaderPath:  " + uploadFolder);
    console.log("session data:  " + req.session.uname);
    console.log("session data:  " + req.session.user);
    session=req.session;
    session.uid=req.body.uid;
    const form = formidable({ multiples: true });
    form.multiples = true;
    form.maxFileSize = 50 * 1024 * 1024; // 5MB
    form.uploadDir = uploadFolder;
    form.on("file", (fields, files) => {
        fs.rename(
          files.filepath,
          form.uploadDir + "/" + files.newFilename,
          () => {
            console.log(
              `Succesfully renamed to ${
                form.uploadDir + "/" + files.newFilename
              }`
            );
          }
        );
      });
      var formfields = new Promise(async function (resolve, reject) {
        form.parse(req, async function (err, fields, files) {
            if (err) {
                console.log("processfileTest003:  ");
                reject(err);
                return;
            }
            console.log("fileTest004:  ");
            //console.log("within form.parse method, subject field of fields object is: " + fields.subjects);
            resolve(fields);
            console.log("fileTest005:  " + JSON.stringify(fields));
            resolve(files);
            pars = JSON.parse(JSON.stringify(fields));
            fil = JSON.parse(JSON.stringify(files));
            console.log("fileTest008:  " + JSON.stringify(fil.Content));
            if (files && fil.Content) {
                fil.Content.filepath = uploadFolder;
                console.log("fileTest009:  " + fil.Content.filepath);
                fName = JSON.stringify(fil.Content.newFilename);
                console.log("fileTest011:   " + fName);
                var fpath = fil.Content.filepath+'/'+fName;
                fpath = fpath.replace(/[\[\]'"]/gi, '');
                console.log("fileTest012:   " + fpath);
            }
        });
    });
    //await new Promise(resolve => setTimeout(resolve, 50));
    var sess = await envsec.processExtForm(form, req, res);
    console.log("SecureEnv_Returned user:  " + JSON.stringify(sess));
    console.log("SecureEnv_Returned user:  " + JSON.stringify(req.session));
    //res.status(200).send(user);
    res.render('secenv.ejs', { user: user });
 });


 app.post('/protocoltrans', async function (req,res, next) {
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
    // curl -s -o response.txt -w "%{http_code}" -F file=@../protoExchangeTokens/saml2jwt_test.jwt --header 'Accept: application/json'  http://localhost:3000/protocoltrans?convrt=oauth-saml
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
               convrtObj = protocolSaml.idpSamlDecoder(parsed, 'resp', conv);
               console.log("saml2oauthValue:resp:   " +JSON.stringify(convrtObj));               
            } else if (conv === "saml-x509"  && parsed.startsWith("<samlp:Response")) {
              //console.log("saml_x509:  " + parsed);
              convrtObj = await protocolSaml.idpSamlDecoder(parsed, 'resp', conv);
              res.end('Successfully Posted' + JSON.stringify(convrtObj));
            } else if ((conv === "saml-oauth" ) && parsed.startsWith("<saml:Assertion")) {                
                console.log("saml_assrt:  " + parsed);
                convrtObj = await protocolSaml.idpSamlDecoder(parsed, 'asrt', conv);
                console.log("saml2oauthValue:asrt:   " + convrtObj);
                res.end('Successfully Posted' + JSON.stringify(convrtObj));
              } else if (conv === "saml-x509"  && parsed.startsWith("<saml:Assertion")) {
                //console.log("saml_x509:  " + parsed);
                convrtObj = await protocolSaml.idpSamlDecoder(parsed, 'asrt', conv);
                uid = protocolSaml.getUid();
                await fsPromises.readFile('./demo_certs/'+uid+'_selfsigned.crt', 'utf8').then(function(result) {
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
      });

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



  app.listen(3000, () => console.log('Your app listening on port 3000'));