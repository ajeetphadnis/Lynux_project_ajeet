/**
 * Module: com.utes.rabbit.amqp2mongo
 *  Consumes one or more AMQP Queues and saves messages to MongoDB collection
 */
'use strict'

const _ = require('lodash')
const Promise = require('bluebird')
const AMQP = require('amqplib')
const MongoClient = require('mongodb').MongoClient
const conMongo = require("../models/com.utes.mongo.connMongo");
const CONFIG = require('convig').env({
  AMQPHOST: 'amqp://guest:guest@localhost',
  MONGODB: 'mongodb://127.0.0.1:27017/auth_users',  
  MONGOCOLLECTION: 'messages',
  TRANSLATECONTENT: true,
  REQUEUEERRORS: false
});

var db;
var client;
var collection = null;
var myDb = null;
var myTab = null;

const queueNames = process.argv.slice(2)
if (!queueNames.length) {
  usage()
  process.exit(1)
}

//connect to database
/**
 * Function: getMongoClient
 * @param {*} uri 
 * @returns 
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
    myDb = client.db('auth_users');
		collection = myDb.collection('messages');
    return client;
}


/**
 * function: usage ()
 * This function verifies that the module app receives required args
 * or else warns the user to provide the required args once again.
 * 
 * 
 * 
 */

async function usage () {
  let bin = require('path').basename(process.argv[1])
  console.error([
    `${bin}: save RabbitMQ Messages from Queues into a MongoDB Collection`,
    `USAGE: ${bin} queue-name [queue-name...]`,
    '',
    'Environment Variables affecting program:',
    '  AMQPHOST: URL of RabbitMQ Server (default: amqp://guest:guest@localhost)',
    '  MONGODB: URL of MongoDB Server (default: mongodb://127.0.0.1:27017/auth_users)',
    '  MONGOCOLLECTION: MongoDB Collection name (default: messages)',
    '  TRANSLATECONTENT: attempt to convert encoding & parse JSON content (default: true)',
    '  REQUEUEERRORS: requeue messages that create an error (default: false)',
    '',
    'This program will keep consuming & saving messages until you interrupt it (CTRL+C)',
    ''
  ].join(require('os').EOL));
}
// new line changed !!!
Promise.try(function () {
  return AMQP.connect(CONFIG.AMQPHOST);
}).then(async function (amqp) {
  return [
    amqp.createChannel(),
    client = await getMongoClient('mongodb://127.0.0.1:27017/') ,
  ]
}).spread(function (channel, db) {
    return Promise.map(queueNames, function subscribe (queue) {
    let opts = {
      translateContent: CONFIG.TRANSLATECONTENT,
      requeueErrors: CONFIG.REQUEUEERRORS
    }
    let consume = saver.bind(null, collection, channel, queue, opts);
    return channel.consume(queue, consume, {})
  });
}).then(function (subscriptions) {
  console.error(
    "[%s] Save to '%s'/'%s'",
    new Date(),
    CONFIG.MONGODB,
    CONFIG.MONGOCOLLECTION
  )
  queueNames.map(function (queue, ix) {
    let cTag = subscriptions[ix].consumerTag
    console.error('[%s] Consuming Queue: %s (cTag=%s)', new Date(), queue, cTag)
  })
}).catch(function (err) {
  console.error(err)
  process.exit(1)
})

/**
 * function:  saver
 * This function takes the db collection, rabbitmq channel, queue name and message
 * and saves it in the database.
 * @param {*} collection 
 * @param {*} channel 
 * @param {*} queueName 
 * @param {*} opts 
 * @param {*} msg 
 */
function saver (collection, channel, queueName, opts, msg) {
  // Attach all message stuff sans content
  let toSave = _.assign({date: new Date(), queue: queueName}, {
    fields: _.omitBy(msg.fields, _.isNil),
    properties: _.omitBy(msg.properties, _.isNil)
  })
  // Strip empty headers
  if (_.isEmpty(toSave.properties.headers)) {
    delete toSave.properties.headers
  }
  // Content Translation
  if (opts.translateContent) {
    toSave.content = convertContent(msg.content, toSave.properties)
    finalTranslate(toSave)
  } else {
    toSave.content = msg.content
  }
  Promise.try(function () {
    return collection.insertOne(toSave)
  }).then(function () {
    return channel.ack(msg)
  }).catch(function (err) {
    console.error(err)
    console.error('[%s] Failed to save: %s', new Date(), JSON.stringify(toSave))
    return channel.reject(msg, opts.requeueErrors)
  })
}


/**
 * Function: finalTranslate
 * THis function takes the content type and messages and encodes the message to
 * base64 and Serializes message for JSON output before sending the data to db.
 * @param {*} base 
 * @returns 
 */
function finalTranslate (base) {
  // Alter object content based on type
  let cType = base.properties.contentType
  if (/^application\/json$/.test(cType)) {
    try {
      base.content = JSON.parse(base.content)
    } catch (e) {
      base.properties.contentType = 'application/octet-stream'
      base.error = _.pick(e, 'message', 'stack', 'code')
    }
  } else if (!/^text\//.test(cType)) {
    if (base.properties.contentType == null) {
      base.properties.contentType = 'application/octet-stream'
    }
  }
  return base
}


/**
 * Function: convertContent
 * This function converts the content to desired format
 * Converts Buffer to a string, altering contentEncoding as appropriate
 * @param {*} buff 
 * @param {*} props 
 * @returns 
 */
function convertContent (buff, props) {
  let cEnc = props.contentEncoding
  cEnc = cEnc && cEnc.toLowerCase().replace(/[^a-z0-9]/g, '')
  // For JSON content without encoding, assume UTF-8
  if (!cEnc && /^application\/json/.test(props.contentType)) {
    props.contentEncoding = 'utf8'
    return buff.toString()
  }
  if (cEnc === 'hex') { // Leave hex strings as HEX-viewable
    props.contentEncoding = 'hex'
    return buff.toString('ascii')
  }
  if (cEnc === 'ascii') { // ASCII text can keep its encoding
    props.contentEncoding = 'ascii'
    return buff.toString('ascii')
  }
  if (cEnc === 'utf8') { // UTF-8 text can keep its encoding
    props.contentEncoding = 'utf8'
    return buff.toString('utf8')
  }
  if (cEnc === 'utf16le' || cEnc === 'ucs2') { // Convert UCS-2/UTF-16 --> UTF-8
    props.contentEncoding = 'utf8'
    return buff.toString(cEnc)
  }
  if (cEnc === 'binary') { // Binary: convert to base64
    props.contentEncoding = 'base64'
    return buff.toString('base64')
  }
  if (cEnc === 'base64') { // Already base64: don't double-encode
    props.contentEncoding = 'base64'
    return buff.toString('ascii')
  }
  // Leave a trace of other unknown encoding before base64
  props.contentEncoding = cEnc ? `base64,${cEnc}` : 'base64'
  return buff.toString('base64')
}
