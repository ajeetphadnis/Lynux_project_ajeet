/**
 * http://usejsdoc.org/ ready states being: 0: disconnected 1: connected 2:
 * connecting 3: disconnecting
 */
require('dotenv').config();
const mongoose = require("mongoose");
var MongoClient = require('mongodb').MongoClient;

var debug = process.env.DEBUG5;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = 'true';
}

debug = 'true';

/**
 * Function: connectMongo
 */
async function connectMongo() {
	try {
		if(debug) {console.log("mongodb_connect:  "+ process.env.DATABASE);}
		await mongoose.connect(process.env.DATABASE, { useNewUrlParser: true, useUnifiedTopology: true }).then(() => {
			const db = mongoose.connection;
			if(debug) {console.log(db.readyState);}
			db.on("error", console.error.bind(console, "connection error: "));
			db.once("open", function () {
			  if(debug) {console.log("Connected successfully");}
			});
			return db;
		});
	} catch(err) {
		console.log("Error:  " + err);
	}
}


/**
 * FUnction: connMongo
 */
async function connMongo () {
	console.log("connMongo:001:  " + process.env.DATABASE);
	var uri = "mongodb://127.0.0.1:27017/auth_users?authSource=admin&keepAlive=true&poolSize=30&socketTimeoutMS=360000&connectTimeoutMS=360000";
	await mongoose.connect(uri, { useUnifiedTopology: true, useNewUrlParser: true }).then(
			  () => { /**
						 * ready to use. The `mongoose.connect()` promise
						 * resolves to mongoose instance.
						 */ 
				  const db = mongoose.connection;
				  if(debug) {console.log(db.readyState);}
				  if(debug) {console.log("connected ....");}
				  return db;
			  },
			  err => { /** handle initial connection error */ 
				  console.log("connError33:  " + err);
			  }
			);
}

var client;

/**
 * FUnction: connMongoClient1
 * @param {*} uri 
 * @returns 
 */
async function connMongoClient1(uri) {
	const url = 'mongodb://mongodb:27017';
	client = null;
	 try{
		 client = new MongoClient(url, { useUnifiedTopology: true, useNewUrlParser: true } );
		 client.connect(function(err) {
		 	console.log('Connected successfully to server');
		 });
	    return client;
	 } catch(err) { console.error(err); 
	 } // catch any mongo error here
	 //finally{ client.close(); } // make sure to close your connection after
	}


	/**
	 * Function: connMongoClient
	 * @param {*} uri 
	 * @returns 
	 */
function connMongoClient(uri)  {
     uri = process.env.DATABASE;      
    try{
        	client = new MongoClient(uri, { useUnifiedTopology:  true } , { useNewUrlParser:  true }, { connectTimeoutMS:  30000 }, {  keepAlive:  1000 });
		 client.connect(function(err) {
		 	console.log('Connected successfully to server');
		 });
	    return client;
	 } catch(err) { console.error(err); 
	 }
}


/**
 * Function: connMongoIDPClient
 * @param {*} uri 
 * @returns 
 */
async function connMongoIDPClient(uri) {
	const url = 'mongodb://mongodb:27017?retryWrites=true&w=majority';
	 try{
		 client = new MongoClient(url, { useUnifiedTopology: true, useNewUrlParser: true } );
		 client.connect(function(err) {
		 	console.log('Connected successfully to server');
		 });
	    return client;
	 } catch(err) { console.error(err); 
	 } // catch any mongo error here
	 //finally{ client.close(); } // make sure to close your connection after
	}



exports.connectMongo = connectMongo;
exports.connMongo = connMongo;
exports.connMongoClient = connMongoClient;
exports.client = client;
exports.connMongoIDPClient = connMongoIDPClient;

 //connectMongo();
//connMongoClient('');
connMongo();