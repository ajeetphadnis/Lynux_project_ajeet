/**
 * http://usejsdoc.org/ ready states being: 0: disconnected 1: connected 2:
 * connecting 3: disconnecting
 */
require('dotenv').config();
const http = require('http');
const mongoose = require("mongoose");
var MongoClient = require('mongodb').MongoClient;
const fs = require('fs');
const express = require('express');
const app = express();

var client = null;
var database = null;
var userid = 'parmer';
var pass = 'parmer';
var debug = 'true';

app.get("/getUser", async function (req, res) {
	console.log("POST:  get user");
	const isUser = await validateUniqueUser(userid, pass);
	console.log("isUser:      " + isUser);
	const status = {
		status: null
	};
	if (isUser) {
		console.log("After user");
		var user = await getAuthUser(userid, pass);
		console.log("got user:  "+ JSON.stringify(user));
		status.status = JSON.stringify(user);
		res.json(status);
	} else {
		res.json(status);
	}
	console.log("End");
})

http.createServer(app).listen(40005);


// connect to database
function connectDB() {
	const uri = process.env.DATABASE;
	console.log("db string:  " + uri);
	try {
		client = new MongoClient(uri, { useUnifiedTopology: true }, { useNewUrlParser: true }, { connectTimeoutMS: 30000 }, { keepAlive: 1000 });
		client.connect(function (err) {
			console.log('Connected successfully to server');
		});
		return client;
	} catch (err) {
		console.error(err);
	}
}


async function validateUniqueUser(email, password) {
	// connect to db
	connectDB();
	const database = await client.connect().catch(err => {
		console.log("Error while connecting to database at : validateUniqueUser");
		console.log(err);
		//client.close();
	});
	//db connection failed
	if (!database) {
		return false;
	}
	// db connection successful - find user
	let user;
	try {
		user = await database.db("auth_users").collection("users").findOne({ nameIdentifier: userid });
	} catch (err) {
		console.log("error while finding user in database at:  validateUniqueUser");
		console.log(err);
		//client.close();
		return false;
	} finally {
		client.close();
		//user not found
		if (user === null || user === undefined) {
			console.log('user not found');
			return false;
		}
		return true;
	}
}

async function getAuthUser(user, pw) {
	client = connectDB();
	database = client.db;

	//databasej connection failed
	if (!database) {
		console.log("Database connection failed !!");
	}
	// database connection successful
	//let getAuthUser;
	try {
		console.log("getUser002:  " + userid);
		const myDb = await client.db('auth_users');
		const myTab = await myDb.collection('users');
		// Query for a user that has nameIdentifier field value in userid
		const query = { nameIdentifier: userid };
		if (debug) { console.log("getUserStruct002:  " + userid); }
		if (debug) { console.log("getUserStruct003:  called ...."); }
		usrStruct = myTab.findOne(query);
		if (usrStruct == null) {
			console.log("getUserStruct004:  usrStruct is null!");
			usrStruct = {};
		}
		exports.usrStruct = usrStruct;
		//global.usrdata = usrStruct;
		if (debug) { console.log("getUserStruct005:  " + JSON.stringify(usrStruct)); }
		if (debug) { console.log(usrStruct); }
		return usrStruct;
	} catch (err) {
		console.log(err);
	} finally {
		//client.close(); 
		return usrStruct;
	}
}



exports.getAuthUser = getAuthUser;
exports.validateUniqueUser = validateUniqueUser;
connectDB();
//getSAMLResp('');
