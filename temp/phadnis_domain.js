/**
 *  Module Name:	phadnis_domain//phadnis_domain.js
 *  Created On:	30. mai 2022
 *  Module Features: 
 */


// Require express and create an instance of it
require('dotenv').config();
const https = require('https');
const http = require('http');
const fs = require('fs');
const express = require('express')
const path = require('path');
const fileUpload = require('express-fileupload');
const Users =  require("./models/com.utes.auth.users");
const conMongo = require("./models/com.utes.mongo.connMongo");
const session = require('express-session');  // session middleware
//const passport = require('passport');  // authentication
const mongoose = require("mongoose");
const mongostore = require("connect-mongo");
mongoose.set('useNewUrlParser', true);
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
mongoose.set('useUnifiedTopology', true);
const bodyParser = require('body-parser');
usrdata = '';
var mongo = require('./models/com.utes.auth.userUtils');
//creating 1 hour from milliseconds
const oneHr = 1000 * 60 * 60 ;
var monCon = conMongo.connMongo();
console.log("moncon:   " + monCon.readyState);
var privateKey =  fs.readFileSync('nodeSrvPrvKey.pem');
var certificate = fs.readFileSync('nodeSrvCert.pem');
var credentials = {key: privateKey, cert: certificate};
app = express();
const port = process.env.PORT ||20443;
app.use(bodyParser.json());
//app.use(forms.array()); 
app.use(express.urlencoded({ extended: true	}));
app.use(bodyParser.urlencoded({ extended: true }));
const MongoStore = mongostore(session);
app.use(session({
    secret: "786Phadnis7654321",
    saveUninitialized:true,
    cookie: { maxAge: oneHr },
    resave: false,
    store: new MongoStore({
          mongooseConnection: mongoose.connection,
          ttl: 14 * 24 * 60 * 60 // save session for 14 days
        })
}));
const routes = require('./api/com.utes.routes');
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'ejs'); // configure template engine
app.set('views', __dirname + '/views'); // set express to look in this folder to render our view
app.use(bodyParser.urlencoded({ extended: true }));
//parse application/vnd.api+json as json
app.use(bodyParser.json({ type: 'application/vnd.api+json' }));
app.use(express.static(path.join(__dirname, 'public'))); // 
app.disable('view cache');
routes(app);
var app = express();

// on the request to root (localhost:3000/)
//app.get('/', function (req, res) {
//    res.send('<b>My</b> first express http server');
//});

// On localhost:3000/welcome
//app.get('/welcome', function (req, res) {
//    res.send('<b>Hello</b> welcome to my http server made with express');
//});

// Change the 404 message modifing the middleware
//app.use(function(req, res, next) {
//    res.status(404).send("Sorry, that route doesn't exist. Have a nice day :)");
//});

// start the server in the port 3000 !
//app.listen(20005, function () {
//    console.log('Example app listening on port 20005.');
//});

https.createServer(app).listen(port);
http.createServer(app).listen(20005);
