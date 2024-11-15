/**
 * http://usejsdoc.org/
 * ready states being:
 * 0: disconnected
 * 1: connected
 * 2: connecting
 * 3: disconnecting
 */
require('dotenv').config();
const mongoose = require("mongoose");
var MongoClient = require('mongodb').MongoClient;
var dburl =   process.env.DATABASE;
var opt = ', { useNewUrlParser: true, useUnifiedTopology: true }';


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
		});
	} catch(err) {
		console.log("Error:  " + err);
	}
}

async function connMongo() {
	const options = {
			  autoIndex: false, // Don't build indexes
			  maxPoolSize: 10, // Maintain up to 10 socket connections
			  serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
			  socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
			  family: 4 // Use IPv4, skip trying IPv6
			};
			mongoose.connect(uri, options);
}


async function connMonP() {
	// Connect to MongoDB
	mongoose.Promise = global.Promise;
	mongoose.connect(dburl, opt);
	mongoose.connection.on('error', (err) => {
	  console.error(`MongoDB connection error: ${err}`);
	  process.exit(1);
	});
	console.log("connected !!!");
}

async function connMonPP () {
	mongoose.connect(dburl, { useUnifiedTopology: true, useNewUrlParser: true }).then(
			  () => { /** ready to use. The `mongoose.connect()` promise resolves to mongoose instance. */ 
				  console.log("connected ....");
			  },
			  err => { /** handle initial connection error */ 
				  console.log("connError:  " + err);
			  }
			);
}


exports.connectMongo = connectMongo;
exports.connMongo = connMongo;
exports.connMonP = connMonP;
exports.connMonPP = connMonPP;

connMonPP();