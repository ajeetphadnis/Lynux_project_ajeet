

/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * https://stormpath.com/blog/beginners-guide-jwts-in-javahttps://stormpath.com/blog/beginners-guide-jwts-in-java
 * 
 * https://www.jsonwebtoken.io/
 */

require('dotenv').config();

const express=require('express');
const expr=express();
const bodyParser = require('body-parser');
var request = require('request');
var fs = require('fs');

const path = require('path');


var debug = process.env.DEBUG12;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
}


//create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: true });
const zipCodeURL = './views/index.html'; 

	/**
	 * 
	 */
	var execServ = { 
		execMSrv:	function (req, res, next) {
			res.sendFile(path.join(__dirname,'../views/execServiceCommnd.html'));
			//res.render('../views/execServiceCommnd.html');
			console.log(req.body.opFIle);
		   }
	};



module.exports = execServ;		



