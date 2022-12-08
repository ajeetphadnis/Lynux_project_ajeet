/**
 * 
 */
 const formidable = require("formidable");
 const path = require('path');
 const fs = require('fs');
 const fsp = require('fs').promises;
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require("cookie-parser");
const sessions = require('express-session');
const { PassThrough } = require('stream');
const envsec = require('./secure_envelop/com.utes.secure.env');
const app = express();
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');app.use(express.static(path.join(__dirname, '/public')));
app.use(bodyParser.urlencoded({ extended: true }));
// creating 24 hours from milliseconds
const oneDay = 1000 * 60 * 60 * 24;
var session;
app.use('/secenv', envsec);
//session middleware
app.use(sessions({
    secret: "Ajeet78654321",
    saveUninitialized:true,
    cookie: { maxAge: oneDay , secure: !true },
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

 
 // files attrs: {"upload_file":{"size":2844,"filepath":"uploads\\43428fb2470119a305d5f3a00","newFilename":"43428fb2470119a305d5f3a00","mimetype":"text/xml","mtime":"
 //	2022-02-26T15:21:50.122Z","originalFilename":"NDCAPXMLO_0009192838-R_20171013-171903.xml"}}
 
 
 
 app.listen(3000, () => console.log('Your app listening on port 3000'));