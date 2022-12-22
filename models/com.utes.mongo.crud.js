/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * 
 * 
 */
require('dotenv').config();
var MongoClient = require('mongodb').MongoClient;

var usrdt;
var usrStruct;
var client;


var debug = process.env.DEBUG6;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
}
debug = 'true';
const {MongoClient} = require('mongodb'),
	  bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose");
const passport              =  require("passport")
var User = require('./com.utes.auth.users');
const conMongo = require("./com.utes.mongo.connMongo");
var Message = require('./com.utes.mongo.messages');
var dbClient;
global.usrdata = '';
if(debug) {console.log('mongo database 001:  ');}


	  var user4 = new User ({
		  nameIdentifier: 'Pratham0984',
		  emailAddress:	'Pratham4.post@us.no',
		  fullname:	'Pratham4 Phadnis',
		  commonName: 'Pratham4',
		  orgName: 'Phadnis',
		  password: 'Pratham00034',
		  mobilePhone: '+4790876543',
		  groups: 'Admin1'
	  });
	
	  
	/**
	 * setUsrdt: 
	 * @param data
	 * @returns
	 */
	function setUsrdt(data) {
		usrdt = data;
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
	function getUsrdt() {
		return usrdt;
	}

	
	/**
	 * listDatabases: 
	 * @param client
	 * @returns
	 */
	async function listDatabases(client){
	    databasesList = await client.db().admin().listDatabases();
	    if(debug) {console.log('mongo database 004:  ');}
	    if(debug) {console.log("Databases:");}
	    databasesList.databases.forEach(db => console.log(` - ${db.name}`));
	};
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	async function getMongoClient(uri) {
		/**
		   * Connection URI. Update <username>, <password>, and <your-cluster-url> to reflect your cluster.
		   * See https://docs.mongodb.com/ecosystem/drivers/node/ for more details
		   */
		  //const uri = "mongodb://Administrator:Ajeet78654321@localhost:27017/test?authSource=Administrator&retryWrites=true&w=majority&ssl=false";
		  /*client = new MongoClient(uri, { useUnifiedTopology: true , useNewUrlParser: true });
		  await client.connect();
		  dbClient = client;
		  return client;	*/
		  client = await conMongo.connMongoClient();
		  if (client ) {
		  	console.log("db client11:  is defined .." );
		  } else {
			console.log("db client22:  is undefined .." );
		  }
		  return client;
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
	async function createUser(user, req, res, next) {
		const myDb = client.db('auth_users');
		const myTab = myDb.collection('users');
		const result = await myTab.insertOne(user);
		console.log(
			      `${result.insertedCount} documents were inserted with the _id: ${result.insertedId}`,
			    );
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
	async function getUser(userid, userpw, req, res, next) {
		console.log("getUser001:   called ....");
		const myDb = client.db('auth_users');
		const myTab = myDb.collection('users');
		// Query for a user that has nameIdentifier field value in userid
	    const query = { nameIdentifier: userid };
	    console.log("getUser002:  " + userid);
	    const options = {
	    	      // sort matched documents in descending order by rating
	    	      sort: { rating: -1 },
	    	      // Include only the `title` and `imdb` fields in the returned document
	    	      projection: { nameIdentifier: 1 , password: 1 },
	    	    };
	    if(debug) {console.log("getUser003:  called ....");}
	    usrdt = await myTab.findOne(query, options);
	    //passport.use(new LocalStrategy(User.authenticate()));
	    //usrdt.verifyPassword(req.body.password);
	    if (usrdt == null) {
	    	usrdt = {};
	    }
	    exports.usrdt = usrdt;
	    //global.usrdata = usrdt;
	    console.log("getUser004:  " + JSON.stringify(usrdt));
	    return usrdt;
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
	async function getUserStruct11(userid, req, res, next) {
		console.log("crud:  getUserStruct001:   called ...." + userid);
		//getMongoClient('');
		if (client) {
			console.log("getUserStruct:db client11:  is defined .." );
		} else {
		  console.log("getUserStruct:db client22:  is undefined .." );
		  await getMongoClient('');
		}

		const myDb = await client.db('auth_users');
		const myTab = await myDb.collection('users');
		// Query for a user that has nameIdentifier field value in userid
	    if(debug) {console.log("getUserStruct002:  " + userid);}
		const query = { nameIdentifier: userid };
	    if(debug) {console.log("getUserStruct003:  called ....");}
	    usrStruct = await myTab.findOne(query);
	    if (usrStruct == null) {
	    	console.log("crud: getUserStruct004:  usrStruct is null!");
	    	usrStruct = {};
	    }
	    exports.usrStruct = usrStruct;
	    //global.usrdata = usrStruct;
	    if(debug) {console.log("getUserStruct005:  " + JSON.stringify(usrStruct));}
	    if(debug) {console.log(usrStruct );}
	    return usrStruct;
	}


	function getUserStruct(userid, req, res, next) {
		var MongoClient = require('mongodb').MongoClient;
		var url = process.env.DATABASE;
		if(debug) {console.log("getUserStruct001:  " + userid);}
		const query = { nameIdentifier: userid };
	    if(debug) {console.log("getUserStruct002:  called ....");}
		MongoClient.connect(url, function(err, db) {
			if (err) throw err;
			var dbo = db.db("auth_users");
			dbo.collection("users").findOne({nameIdentifier: userid}, function(err, result) {
				if (err) throw err;
				console.log("getUserStruct003:  " + result);
				db.close();
				return result;
			});
		});
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
	async function deleteUser(userid, req, res, next) {
		const myDb = client.db('auth_users');
		const myTab = myDb.collection('users');
		// Query for a user that has nameIdentifier field value in userid
	    const query = { nameIdentifier: userid };
	    await myTab.deleteOne(query).then((result) => {
	        console.log('user deleted');
	        console.log(result);
	    }).catch((err) => {
	        console.log(err);
	    }).finally(() => {
	        //client.close();
	    });
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
	async function updateUser(userid, updat, req, res, next) {
		const myDb = client.db('auth_users');
		const myTab = myDb.collection('users');
		// Query for a user that has nameIdentifier field value in userid
		// const updat = { $set: { fieldname: fieldvalue } };
	    const query = { nameIdentifier: userid };
	    await myTab.updateOne(query, updat ).then((result) => {
	        console.log('user updated');
	        console.log(result);
	    }).catch((err) => {
	        console.log(err);
	    }).finally(() => {
	        //client.close();
	    });
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
	async function createListing(client, newListing){
	    const result = await client.db("sample_airbnb").collection("listingsAndReviews").insertOne(newListing);
	    console.log(`New listing created with the following id: ${result.insertedId}`);
	}
	
module.exports.listDatabases = listDatabases;
module.exports.getMongoClient = getMongoClient;
module.exports.createUser = createUser;
module.exports.getUser = getUser;
module.exports.deleteUser = deleteUser;
module.exports.updateUser = updateUser;
module.exports.getUsrdt = getUsrdt;
module.exports.setUsrdt = setUsrdt;
module.exports.dbClient = dbClient;
module.exports.usrdt = usrdt;
module.exports.usrStruct = usrStruct;
module.exports.getUserStruct = getUserStruct;

//const url = 'mongodb://localhost:27017/auth_users\', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
//getMongoClient(url);