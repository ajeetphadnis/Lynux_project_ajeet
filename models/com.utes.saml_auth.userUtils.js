/**
 * 
 */
require('dotenv').config();
const express               =  require('express'),
      // app = express(),
      mongoose              =  require("mongoose"),
      bodyParser            =  require("body-parser");
const session = require('express-session');  // session middleware
      const Users                 =  require("./com.utes.auth.users");
      var usrDb = require('./com.utes.mongo.crud');
      var usrdt = require('./com.utes.mongo.crud');
      const mongostore = require("connect-mongo");
      const conMongo = require("./com.utes.mongo.connMongo");
      const samlAssrt = require("../service/com.utes.saml.user_initiated");
      const fs = require("fs");

      
      var client;
      var db;
      var usrStruct;
      
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

    var user = {
        uid: '',
        pass: '',
        serv: '',
        samlassrt: '',
        jwtoken: '',
        x509token: '',
        newuser: {}
    };
    
    
    var debug = process.env.DEBUG8;
    if (debug === 'true') {
    	debug = 'true';
    } else {
    	debug = null;
    }
    
    const sleep = (time) => {
    	  return new Promise((resolve) => {
    	    setTimeout(resolve, time);
    	  });
    	}


    /**
     * connMongo:  
     * @param req
     * @param res
     * @returns
     */
	async function connMongo(req, res) {
		// Connection URL
    	  //const url = 'mongodb://localhost:27017/auth_users\', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
    	  const url = process.env.DATABASE+', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
    	  client = await conMongo.connMongoClient(url);	
    	  return client;
	};
	
	
	/**
	 * getUserStruct:
	 * @param userid
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function getUserStruct(userid, req, res, next) {
		try{
			console.log("getUserStruct001:   called ...." + userid);
			client = await conMongo.connMongoIDPClient('');
		    console.log("connected to mongo !!!");
		    const myDb = client.db('auth_users');
			const myTab = myDb.collection('users');
			// Query for a user that has nameIdentifier field value in userid
		    const query = { nameIdentifier: userid };
		    console.log("getUserStruct002:  " + userid);
		    if(debug) {console.log("getUserStruct003:  called ....");}
		    usrStruct = await myTab.findOne(query);
		 // do something
		    //await sleep(50);
		    // do something else
		    console.log(usrStruct);
		 } catch(err) { console.error(err); 
		 } // catch any mongo error here
		 finally {
			    if(client)
			      await client.close();
			  }
		    if (usrStruct == null) {
		    	console.log("getUserStruct004:  usrStruct is null!");
		    	usrStruct = {};
		    }
		    exports.usrStruct = usrStruct;
		    return usrStruct;
		//});
	}
	
	
	/**
	 * getDemoUserSAMLAsser: 
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function getDemoUserSAMLAssert(req, res, next) {
		try{
			if (req.method === 'GET' && req.method !== 'POST') {
				console.log('getDemoUserSAMLAssert:GET');
				req.on('data', function (chunk) {
			        console.log('GOT DATA!' + JSON.stringify(data));
			    });
			}
			
			if (req.method === 'POST' && req.method !== 'GET') {
				console.log('getDemoUserSAMLAssert: POST');
				console.log('getDemoUserSAMLAssert: Got body:', req.body);
				if (req.body.udata) {
					var udat = JSON.parse(JSON.stringify(req.body.udata));
					JSON.parse(udat, (key, value) => {
						  if (typeof value === 'string') {
						    console.log("key:  " + key + "  value:  " + value);
						    if(key === 'uid') user.uid = value;
						    if(key === 'ope') user.oprf = value;
						    if(key === 'upass') user.pass = value;
						  }
						  //return value;
						  user.serv = user.oprf;
					});
					console.log("getDemoUserSAMLAsser001:   called ...." + user.uid);
					await samlAssrt.getSamlAssert(user.uidd, req, res, next);
					await fs.readFile('./demo_certs/'+user.uid+'_signedAssert.xml', 'utf8' , (err, data) => {				
						if (err) {
							console.error(err);
							return;
						} else {
							user.newuser = new Users();
							user.uid = user.uid;
							user.newuser.nameIdentifier = user.uid;
							user.newuser.password = user.uid;
							user.pass = user.uid;
							user.samlassrt = data.toString('utf8');
						}
						
					});
					await res.status(200).send({ user: user, user, newuser: user.newuser});
				}
			}
		 } catch(err) { console.error(err); 
		 } // catch any mongo error here
		 finally {
			    if(client)
			      await client.close();
			  }
	}
	
	
	
	/**
	 * getUserStructMail: 
	 * @param userMail
	 * @param password
	 * @param req
	 * @param res
	 * @param next
	 * @returns
	 */
	async function getUserStructMail(userMail, password, req, res, next) {
		try{
			console.log("getUserStruct001:   called ...." + userMail + "   pw:  " + password);
			client = await conMongo.connMongoIDPClient('');
		    console.log("connected to mongo !!!");
		    const myDb = client.db('auth_users');
			const myTab = myDb.collection('users');
			// Query for a user that has nameIdentifier field value in userid
		    const query = { emailAddress:userMail };
		    console.log("getUserStruct002:  " + userMail);
		    if(debug) {console.log("getUserStruct003:  called ....");}
		    usrStruct = await myTab.findOne(query);
		 // do something
		    //await sleep(50);
		    // do something else
		    var udata = JSON.parse(JSON.stringify(usrStruct));
		    if(debug) {console.log("UserId:  " + udata.nameIdentifier + "   userpw:  " + udata.password);}
		    //const isMatching = await bycrpt.compare(password, udata.password);
		    if (udata.password === password) {
		    	//res.json({ ok: "USER SIGNED" });
		        console.log("wellcome user signed");
			    exports.usrStruct = usrStruct;
			    return usrStruct;
		    } else {
		    	//res.json({ ok: "USER NOT SIGNED" });
		        console.log("Invalid Credential !!");
		    }
		 } catch(err) { console.error(err); 
		 } // catch any mongo error here
		 finally {
			    if(client)
			      await client.close();
			  }
		    if (usrStruct == null) {
		    	console.log("getUserStruct004:  usrStruct is null!");
		    	usrStruct = {};
		    }
		//});
	}
	
	
	/**
	 * setSAMLAssert:  
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

		
	
	exports.connMongo = connMongo;
	exports.getUserStruct = getUserStruct;
	exports.sleep = sleep;
	exports.usrStruct = usrStruct;
	exports.getUserStructMail = getUserStructMail;
	exports.setSAMLAssert = setSAMLAssert;
	exports.getDemoUserSAMLAssert = getDemoUserSAMLAssert;
	//client = connMongo('', '');
	//getUserStruct('rohanaggarwal', '', '', '');