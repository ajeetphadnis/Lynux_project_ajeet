/**
 * http://usejsdoc.org/
 */
require('dotenv').config();
const https = require('https');
const http = require('http');
const fs = require('fs');
const express = require('express');
var Gallery = require('express-photo-gallery');
const path = require('path');
const fileUpload = require('express-fileupload');
const Users =  require("./models/com.utes.auth.users");
const conMongo = require("./models/com.utes.mongo.connMongo");
const session = require('express-session');  // session middleware
//const passport = require('passport');  // authentication
const mongoose = require("mongoose");
const mongostore = require("connect-mongo");
const cors = require('cors');
//var multer = require('multer');
//var forms = multer();
//LocalStrategy = require("passport-local").Strategy,
//passportLocalMongoose =	require("passport-local-mongoose"),
mongoose.set('useNewUrlParser', true);
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
mongoose.set('useUnifiedTopology', true);
const bodyParser = require('body-parser');
usrdata = '';
var mongo = require('./models/com.utes.auth.userUtils');
//creating 1 hour from milliseconds
const oneHr = 1000 * 60 * 60 ;
//session middleware

//mongoose.connect('mongodb://localhost:27017/auth_users', { useNewUrlParser: true, useUnifiedTopology: true }).then(() => {
    /*mongoose.connect(process.env.DATABASE, { useNewUrlParser: true, useUnifiedTopology: true }).then(() => {
	//var dbUrl = 'mongoose.connection.mongodb://localhost:27017/auth_users';
	var dbUrl = process.env.DATABASE;
	var dbOps = 'mongoOptions: {useNewUrlParser: true, useUnifiedTopology: true }';*/
	var monCon = conMongo.connMongo();
	console.log("moncon:   " + monCon.readyState);
	var privateKey =  fs.readFileSync('nodeSrvPrvKey.pem');
	var certificate = fs.readFileSync('nodeSrvCert.pem');
	var credentials = {key: privateKey, cert: certificate};
	app = express();
	const port = process.env.PORT ||30010;
	app.use(bodyParser.json());
	//app.use(forms.array()); 
	app.use(express.static(path.join(__dirname, 'VIDEO')));
	app.use(express.static(path.join(__dirname, 'images')));
	app.use(express.urlencoded({ extended: true	}));
	app.use(bodyParser.urlencoded({ extended: true }));
	const corsOptions = {
	  origin: "https://phadnis.no",
	  credentials: false,
	};
	app.use(cors(corsOptions));
	const MongoStore = mongostore(session);
	app.use(session({
	    secret: "786Phadnis7654321",
	    saveUninitialized:true,
	    cookie: { maxAge: oneHr, secure: true,
			httpOnly: true,
			SameSite: 'None'  },
	    resave: false,
	    store: new MongoStore({
	          mongooseConnection: mongoose.connection,
	          ttl: 14 * 24 * 60 * 60 // save session for 14 days
	        })
	}));
	//app.use(passport.initialize());
	//app.use(passport.session());
	// To use with sessions
	//passport.use(new LocalStrategy(Users.authenticate()));
	//passport.serializeUser(Users.serializeUser());
	//passport.deserializeUser(Users.deserializeUser());
	app.use((req, res, next) => {
		res.header("Access-Control-Allow-Origin", "*");
		res.header(
			"Access-Control-Allow-Methods",
			"OPTIONS, GET, POST, PUT, PATCH, DELETE"
		);
		res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
		next();
	});
	var options = {
		title: 'Jyotsnas Photo Gallery'
	};

	app.use('/images', Gallery('images', options));
	app.use('/VIDEO', Gallery('VIDEO', options));
	
	const routes = require('./api/com.utes.routes');
	app.engine('html', require('ejs').renderFile);
	app.set('view engine', 'ejs'); // configure template engine
	app.set('views', __dirname + '/views'); // set express to look in this folder to render our view
	app.use(bodyParser.urlencoded({ extended: true }));
	//parse application/vnd.api+json as json
	app.use(bodyParser.json({ type: 'application/vnd.api+json' }));	
	app.use(express.static(path.join(__dirname, 'public'))); // 
	app.use(express.static(path.join(__dirname, 'demo_docs'))); // 
	app.use(express.static(path.join(__dirname, 'paperjsv01215')));
	app.disable('view cache');
	routes(app);
	https.createServer(credentials,app).listen(port);
	http.createServer(app).listen(30082);
//});
