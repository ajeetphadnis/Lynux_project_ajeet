/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * https://codebun.com/login-registration-nodejsexpress-mongodb/
 * 
 *        
 */
const mongoose = require("mongoose");
var crypto = require('crypto');
require('dotenv').config();

var debug = process.env.DEBUG2;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
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
const UserSchema = new mongoose.Schema(
    {
	nameIdentifier : String,
	emailAddress : String,
	fullname : String,
	commonName : String,
	orgName : String,
	password : String,
	mobilePhone : String,
	groups : String,
	hash : String,
	salt : String
    });

//Method to set salt and hash the password for a user
UserSchema.methods.setPassword = function(password) {

    // Creating a unique salt for a particular user
    this.salt = crypto.randomBytes(16).toString('hex');

    // Hashing user's salt and password with 1000 iterations,

    this.hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64, `sha512`)
	    .toString(`hex`);
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
// Method to check the entered password is correct or not
UserSchema.methods.validPassword = function(password) {
    var hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64, `sha512`)
	    .toString(`hex`);
    return this.hash === hash;
};

module.exports = mongoose.model("User", UserSchema);
