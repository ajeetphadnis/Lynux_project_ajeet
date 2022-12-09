/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * http://usejsdoc.org/ This login app is based on :
 * https://codebun.com/login-registration-nodejsexpress-mongodb/ Problem was
 * connect-mongo v 4 so downgraded the version of connect-mongo package from v4
 * to v3 try unistalling connect mongo - npm uninstall connect-mongo then
 * install connect v3 - npm i connect-mongo@3
 */
var randusr;
var user;
require('dotenv').config();

const express               =  require('express'),
	bodyParser = require('body-parser'),
      // app = express(),
      mongoose              =  require("mongoose");
      const session = require('express-session');  // session middleware
      const Users =  require("./com.utes.auth.users");
      const randu = require("./com.utes.demo.randname_gen");
      var usrDb = require('./com.utes.mongo.crud');
      var usrdt = require('./com.utes.mongo.crud');
      const mongostore = require("connect-mongo");
      const demoCert = require('../x509_utils/com.utes.security.createDemoSelfSignedCert');
      const assertSaml = require('../saml_assert/com.utes.saml.user_initiated');
      const pem2jwks  = require('../jwks/com.utes.pem-to-jwt');
      const conMongo = require("./com.utes.mongo.connMongo");
      const nodeMailer = require('nodemailer');
//      var multer = require('multer');
//      var forms = multer();
      global.usrdata;
      const assert = require('assert');
      const models = { Users};
      var client;
      var db;
      var newuser = new Users ({
    	  nameIdentifier: '',
    	  emailAddress: '',
    	  fullname: 'dummy',
    	  commonName: '',
    	  orgName: '',
    	  password: '',
    	  mobilePhone: '',
    	  groups: '',
    });

  user = {
		  uid: '',
		  pass: '',
		  serv: '',
		  srctxt: '',
		  destxt: '',
		  oprt: '',
		  randusr: '',
		};
  
  	var debug = process.env.DEBUG3;
  	if (debug === 'true') {
  		debug = 'true';
  	} else {
  		debug = null;
  	}


    
    /**
     * sleep: function is used to create delays if needed
     * @param ms
     * @returns
     */
    function sleep(ms) {
    	  return new Promise((resolve) => {
    	    setTimeout(resolve, ms);
    	  });
    	}

	
    /**
     * connMongo: This method connects to UTES database.
     * @param req
     * @param res
     * @returns
     */
	function connMongo(req, res) {
		// Connection URL
    	  //const url = 'mongodb://localhost:27017/auth_users\', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
    	  const url = process.env.DATABASE+', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
    	  usrDb.getMongoClient(url);		
	};
	
	
	/**
	 * protocolconvert_start: THis method handles the initialization of the app.
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	function protocolconvert_start(req, res, next) {
		// mongoose.connect("mongodb://localhost:27017/auth_users");
		//const connection = mongoose.createConnection("mongodb://localhost:27017/auth_users");
		var monCon = conMongo.connMongo();
		const connection = mongoose.connection;
		const MongoStore = mongostore(session);
		const sessionStore = new MongoStore({ mongooseConnection: connection, collection: 'sessions' });
		res.render('protocolconvert_start');
	};
	
	
	/**
	 * profile_user: THis function handles user profile end point
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	function profile_user(req, res, next) {
		res.render('profile_user');
	};
	
	
	/**
	 * login_user: this function allows a user login if the user
	 * exists in the utes database.
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function login_user(req, res, next) {
		var exists = false;
		var resp = res;
		if (req.method === 'GET' && req.method !== 'POST') {
			if(debug) {console.log("login_user: " + req.method);}
			res.render('login_user');
			// res.sendFile('login_user.html');
		  }
		if (req.method === 'POST' && req.method !== 'GET') {
			 // Find user with requested email
		    Users.findOne({ nameIdentifier : req.body.nameIdentifier }, function(err, user) { 
		        if (user === null) { 
//		            return res.status(400).send({ 
//		                message : "User not found."
//		            }); 
		            res.render('protocolconvert_start');
		        } 
		        else { 
		            if (user.validPassword(req.body.password)) { 
//		                return res.status(201).send({ 
//		                    message : "User Logged In", 
//		                }) 
		            req.app.session = req.session;
					req.app.session.clientId = req.body.nameIdentifier;
					req.app.session.clientPw = req.body.password;
		        	user.uid = req.body.nameIdentifier;
		        	user.pass = req.body.password;
				user.newuser = usrDb.usrdt;
				resp.render("../views/form_convrt",
		                {
		                    user: user
		                }
		        );
		            } 
		            else { 
//		                return res.status(400).send({ 
//		                    message : "Wrong Password"
//		                }); 
		        	res.render('login_user');
		            } 
		        } 
		    }); 
		}; 
	};
	
	
	/**
	 * register_user: This function registers a new user in the
	 * system and creates a record in the database.
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	function register_user(req, res, next) {
		if (req.method === 'GET' && req.method !== 'POST') {
			res.render('register_user');
		}
		if (req.method === 'POST' && req.method !== 'GET') {
		    var newuser = new Users();
			newuser.nameIdentifier = req.body.nameIdentifier;
			newuser.emailAddress = req.body.emailAddress;
			newuser.fullname = req.body.fullname;
			newuser.commonName = req.body.commonName;
			newuser.orgName = req.body.orgName;
			newuser.password = req.body.password;
			newuser.mobilePhone = req.body.mobilePhone;
			newuser.groups = req.body.groups;
			connMongo(req, res);
			// Call setPassword function to hash password
	                newuser.setPassword(req.body.password); 
	             // Save newUser object to database
	                newuser.save((err, Users) => { 
	                    if (err) { 
	                        return res.status(400).send({ 
	                            message : "Failed to add user."
	                        }); 
	                    } 
	                    else { 
//	                        return res.status(201).send({ 
//	                            message : "User added successfully."
//	                        }); 
	                        res.render("../views/protocolconvert_start",
	        	                {
	        	                    user: user
	        	                }
	        	        );
	                    } 
	                }); 
	            }; 

		}
	
	
	/**
	 * demo_user: THis function handles demo used endpoint.
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function demo_user(req, res, next) {
		if (req.method === 'GET' && req.method !== 'POST') {
			console.log("demo_user: GET: " + JSON.stringify(req.body));
			req.app.use(bodyParser.urlencoded({ extended : true }));
			if(debug) {console.log("demo_user: GET: " + JSON.stringify(req.body));}
			var newuser = new Users();
			newuser.fullname = 'dummy.dummy';
			randusr = JSON.stringify(newuser);
			res.render('demo_user',  
                	{ randusr: randusr
                	});
		}
		if (req.method === 'POST' && req.method !== 'GET') {
			if (!req.body.uid ) return;
		    //req.app.use(bodyParser.urlencoded({ extended : true }));
			req.app.use(express.urlencoded({ extended: true	}));
		    var newuser = new Users();
		    if(debug) {console.log("UID:   " + req.body.demoname);}
			newuser.nameIdentifier = req.body.uid;
			newuser.emailAddress = req.body.demomail;
			newuser.fullname = req.body.demoname;
			newuser.commonName = req.body.demoname;
			newuser.orgName = req.body.demoname;
			newuser.password = req.body.uid;
			newuser.mobilePhone = '0078563412';
			newuser.groups = "demo";
			var pass = req.body.uid;
			req.app.session = req.session;
		    req.app.session.uid = req.body.uid;
		    req.app.session.upw = req.body.uid;
        	await demoCert.createDemoSelfSignedCert(newuser.nameIdentifier, '', newuser, newuser.password, req, res, next);
        	await assertSaml.getDemoSamlAssert(newuser.nameIdentifier, req, res, next);
        	var filpem = './demo_certs/'+newuser.nameIdentifier+'_selfsigned.crt';
			var filPrvKey = './demo_certs/'+newuser.nameIdentifier+'_certp12b64.p12';
			await pem2jwks.cre_demopem2jwt(newuser.nameIdentifier, filPrvKey, filpem, user.pass, '', req, res, next);
			connMongo(req, res);
			// Call setPassword function to hash password
	        newuser.setPassword(req.body.uid); 
	        randusr = JSON.stringify(newuser);
	        // Check if the user exists in database
	        // Find user with requested email
		    Users.findOne({ nameIdentifier : req.body.uid }, function(err, user) { 
		        if (user === null) { 
		        	// Save newUser object to database
		        	newuser.save((err, Users) => { 
		        		if (err) { 
		        			return res.status(400).send({ 
		        				message : "Failed to add user."
		        			}); 
		        		} else { 
		        			res.render("demo_user",
		        					{
		        						randusr: randusr
		        					}
		        			);
		        		} 
		        	}); 
		        } else { 
        			res.render("demo_user",
        					{
        						randusr: randusr
        					}
        			);
        		} 
		    });
		}
	}
	
	
	/**
	 * utesdemo: This function handles utes demo  Get and POST methods
	 * for userUtils module.
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function utesdemo(req, res, next) {
		//req.app.set("../views", path.join(__dirname));
		//req.app.set("view engine", "ejs");
		//create application/x-www-form-urlencoded parser
		//var urlencodedParser = bodyParser.urlencoded({ extended: true });
		//var randus;
		var newuser = new Users();
		newuser.fullname = 'dummy.dummy';
		randusr = JSON.stringify(newuser);
		//randusr.fullname = 'duymmy.dummy';
		if (req.method === 'GET' && req.method !== 'POST') {
			res.render('demo_user',  
                	{ randusr: randusr
                	});
		}
		if (req.method === 'POST' && req.method !== 'GET') {
		    var newuser = new Users();
		    rnduser = randu.generateDemoUser(1);
		    randus = rnduser.nameIdentifier;
		    user.uid = rnduser.nameIdentifier;
		    user.randusr = rnduser.nameIdentifier;
		    user.pass = rnduser.password;
		    //user. = newuser;
		    /*res.render("utesdemo",  
		                     	{ randusr: ''
                	});*/
		    //var usrObj = JSON.parse(rnduser);
		    if(debug) {console.log("newuser: " + JSON.stringify(rnduser));}
			newuser.nameIdentifier = rnduser.nameIdentifier;
			newuser.emailAddress = rnduser.emailAddress;
			newuser.fullname = rnduser.fullname;
			newuser.commonName = rnduser.commonName;
			newuser.orgName = rnduser.orgName;
			newuser.password = rnduser.password;
			newuser.mobilePhone = rnduser.mobilePhone;
			newuser.groups = 'demo';	
        	await demoCert.createDemoSelfSignedCert(newuser.nameIdentifier, '', newuser, newuser.password, req, res, next);
        	await assertSaml.getDemoSamlAssert(newuser.nameIdentifier, req, res, next);
        	var filpem = './demo_certs/'+newuser.nameIdentifier+'_selfsigned.crt';
			var filPrvKey = './demo_certs/'+newuser.nameIdentifier+'_certp12b64.p12';
			await pem2jwks.cre_demopem2jwt(newuser.nameIdentifier, filPrvKey, filpem, newuser.password, '', req, res, next);
			connMongo(req, res);
			// Call setPassword function to hash password
	        newuser.setPassword(rnduser.password);
	        randusr = JSON.stringify(newuser);
         // Save newUser object to database
	        newuser.save((err, Users) => { 
                if (err) { 
                    return res.status(400).send({ 
                        message : "Failed to add user."
                    }); 
                } else { 
//	                        return res.status(201).send({ 
//	                            message : "User added successfully."
//	                        }); 
                	sleep(100000);
                	//var tmpu = JSON.stringify(randusr);
                	var obj = JSON.parse(randusr);
                	if(debug) {console.log("User added successfully:  " + obj.fullname);}
                   res.render("demo_user",  
                    	{ randusr: randusr
                    	});
	               } 
	           });
		}
	         /*return await newuser.save ()
	        .then(user => {
	        	randusr = 'Ajeet is not satisfied !!!';
	        	user.uid = rnduser.nameIdentifier;
	        	sleep(100000000);
	        	console.log('The user ' + demousr.uid + ' has been added.');
	        	res.render("utesdemo",  
                    	{ user: user
                    	});
	        })
	        .catch(err => handleError(err))
	        .finally(() => console.log('Insert Done!!'));
		}*/
	}


	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	function nav_side (req, res, next) {
		res.render("../views/nav_side");
	}
	
	
	function clientClose() {
		client.close();
	};
	
	
	/**
	 * Function: sendEmail
	 * @param {*} req 
	 * @param {*} res 
	 * @param {*} next 
	 */
	function sendEmail(req, res, next) {
		if (req.method === 'POST' && req.method !== 'GET') {
			var mname = req.body.name;
			var email  = req.body.email;
			var subject = req.body.subject;
			var message = req.body.message;
			if (debug) { console.log("sendEmail: post: " + JSON.stringify(req.body)); } 
			let transporter = nodeMailer.createTransport({
		          host: process.env.RECV_HOST,
		          port: process.env.RECV_PORT,
		          secure: process.env.RECV_SECURE,
		          auth: {
		              user: process.env.RECV_USER,
		              pass: process.env.RECV_PW
		          }
		      });
		      let mailOptions = {
		          from: email, // sender address
		          to: process.env.RECV_EMAIL, // list of receivers
		          subject: subject, // Subject line
		          text: message, // plain text body
		          html: '<b>'+message+'</b>' // html body
		      };
	
		      transporter.sendMail(mailOptions, (error, info) => {
		          if (error) {
		              return console.log(error);
		          }
		          console.log('Message %s sent: %s', info.messageId, info.response);
		              res.render('index');
		      });
		}
	};
	
	
	/**
	 * Function: setSAMLAssert:  
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	 function setSAMLAssert(req, res, next) {
		var assertXml = req.query.assertXml;
		//var usr = new user;
		user.samlassrt = assertXml;
		console.log("Query:   " + assertXml);
		if (req.method === 'GET' && req.method !== 'POST') {
			res.render("../views/samlAssert",
            {
				user: user
            });
		}
		if (req.method === 'POST' && req.method !== 'GET') {
			res.render("../views/samlAssert",
            {
				user: user
            });
		}
	}

// exports.connectMongo = connectMongo;
exports.connMongo = connMongo;
exports.client = client;
exports.db = db;
exports.protocolconvert_start = protocolconvert_start;
exports.profile_user = profile_user;
exports.login_user = login_user;
exports.register_user = register_user;
exports.nav_side = nav_side;
exports.utesdemo = utesdemo;
exports.demo_user = demo_user;
exports.sendEmail = sendEmail;
exports.setSAMLAssert = setSAMLAssert;

//demo_user('', '', '');
//randuser('', '', '');