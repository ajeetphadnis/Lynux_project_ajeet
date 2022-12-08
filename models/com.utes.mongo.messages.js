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

var debug = process.env.DEBUG7;
if (debug === 'true') {
	debug = 'true';
} else {
	debug = null;
}


const mongoose =  require("mongoose");
passportLocalMongoose =  require("passport-local-mongoose"); 
const messageSchema = new mongoose.Schema(
  {
    text: {
      type: String,
      required: true,
    },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true },
);

messageSchema.plugin(passportLocalMongoose);
module.exports = mongoose.model('Message', messageSchema);
