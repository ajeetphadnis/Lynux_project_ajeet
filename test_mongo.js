/**
 * http://usejsdoc.org/ ready states being: 0: disconnected 1: connected 2:
 * connecting 3: disconnecting
 */
require('dotenv').config();
const mongoose = require("mongoose");
var MongoClient = require('mongodb').MongoClient;
const fs = require('fs');

async function connectMongo() {
	try {
		console.log("mongodb_connect:  "+ process.env.DATABASE);
		await mongoose.connect(process.env.DATABASE, { useNewUrlParser: true, useUnifiedTopology: true }).then(() => {
			const db = mongoose.connection;
			console.log(db.readyState);
			db.on("error", console.error.bind(console, "connection error: "));
			db.once("open", function () {
			  console.log("Connected successfully");
			});
			return db;
		});
	} catch(err) {
		console.log("Error:  " + err);
	}
}


async function connMongo () {
	await mongoose.connect(process.env.DATABASE, { useUnifiedTopology: true, useNewUrlParser: true }).then(
			  () => { /**
						 * ready to use. The `mongoose.connect()` promise
						 * resolves to mongoose instance.
						 */ 
				  const db = mongoose.connection;
				  console.log(db.readyState);
				  console.log("connected ....");
				  return db;
			  },
			  err => { /** handle initial connection error */ 
				  console.log("connError:  " + err);
			  }
			);
}


async function connMongoClient(uri) {
	let client, db;
	 try{
	    client = await MongoClient.connect(process.env.DATABASE, { useUnifiedTopology: true, useNewUrlParser: true });
	    //db = client.db(dbName);
	    // let dCollection = db.collection('collectionName');
	    // let result = await dCollection.find();
	    // let result = await dCollection.countDocuments();
	    // your other codes ....
	    // return result.toArray();
	    return client;
	 } catch(err) { console.error(err); 
	 } // catch any mongo error here
	 //finally{ client.close(); } // make sure to close your connection after
	}


function getSAMLResp(path) {
	fs.readFile(process.env.SAML_SRV+"/saml_resp.xml", "utf-8", function (error, text) {
		if (error) {
			console.log("xml file read error:    " + error);
		} else {
			console.log("XML_Content:  "+ text);
		}
	});
}



exports.connectMongo = connectMongo;
exports.connMongo = connMongo;
exports.connMongoClient = connMongoClient;
exports.getSAMLResp = getSAMLResp;

// connectMongo();
getSAMLResp('');