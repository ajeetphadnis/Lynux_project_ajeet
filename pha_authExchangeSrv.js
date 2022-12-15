/**
 * http://usejsdoc.org/
 */
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
<<<<<<< HEAD
	app.use(express.static(path.join(__dirname,'demo_docs')));
	app.use(cors({
		credentials: true,
		preflightContinue: true,
		methods: ['GET', 'POST', 'PUT', 'PATCH' , 'DELETE', 'OPTIONS'],
		origin: true,
		optionsSuccessStatus: 200
	}));
=======
>>>>>>> f9a5b687fefdb8f75c38346b2f8bca5f8b4c6313
	const port = process.env.PORT ||3443;
	app.use(bodyParser.json());
	//app.use(forms.array()); 
	app.use(express.urlencoded({ extended: true	}));
	app.use(bodyParser.urlencoded({ extended: true }));
	const MongoStore = mongostore(session);
	app.use(session({
	    secret: "786Phadnis7654321",
	    saveUninitialized:true,
<<<<<<< HEAD
	    cookie: { maxAge: oneHr, secure: true,
			httpOnly: true,
			SameSite: 'None'  },
=======
	    cookie: { maxAge: oneHr },
>>>>>>> f9a5b687fefdb8f75c38346b2f8bca5f8b4c6313
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
	https.createServer(credentials,app).listen(port);
	http.createServer(app).listen(3005);
//});
