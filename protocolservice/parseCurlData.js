const events = require('events');
const fs = require('fs');
const readline = require('readline');
var Stream = require('stream');
var outStream = new Stream();
var curlData = '';


async function processLineByLine11(datStr, mode) {
  var lcnt = 0;
  var done = false;
  try {
    var Readable = require('stream').Readable;
    var strm = new Readable();
    strm.push(datStr);    // the string you want
    strm.push(null);      // indicates end-of-file basically - the end of the stream
    const rl = readline.createInterface({
      input: strm,   //fs.createReadStream(strm),
      crlfDelay: Infinity
    });

    rl.on('line', (line) => {
      lcnt++;
      // for x509 its cnt 3. for oauth its 4 
      if (!done) {
        if (lcnt > 3 && (line.indexOf('--------------------------') === -1)) {
          curlData += line;
          console.log(`3Line from file: ${lcnt}  ${line}`);
          //done = true;
        }
      }
      if (!done) {
        if (lcnt > 4 && (line.indexOf('--------------------------') === -1)) {
          curlData += line;
          //done = true;
          console.log(`4Line from file: ${lcnt}  ${line}`);
        }
      }
    });
    done = true;
    rl.on('close', function () {
      // do something with incomingData
      console.log("curlData:   " + curlData);
      exports.curlData;
      done = false;
      return curlData;
    });
    //await events.once(rl, 'close');
    /* console.log('Reading file line by line with readline done.');
    const used = process.memoryUsage().heapUsed / 1024 / 1024;
    console.log(`The script uses approximately ${Math.round(used * 100) / 100} MB`); */
  } catch (err) {
    console.error(err);
  }
}


async function processLineByLine(datStr) {
  var lcnt = 0;
  datStr = datStr.trim();
  console.log("processLineByLine001:   " + datStr);
  return new Promise(function (resolve, reject) {
    try {
      var Readable = require('stream').Readable;
      var strm = new Readable();
      strm.push(datStr);    // the string you want
      strm.push(null);      // indicates end-of-file basically - the end of the stream
      const rl = readline.createInterface({
        input: strm,   //fs.createReadStream(strm),
        crlfDelay: Infinity
      });

      rl.on('line', (line) => {
        lcnt++;
        if (lcnt > 3 && (line.indexOf('--------------------------') === -1)) {
          curlData += line;
          console.log(`3 Line from file: ${lcnt}  ${line}`);
        }
        console.log('curlData:  ' + curlData);
        /* if (lcnt > 4 && (line.indexOf('--------------------------') === -1)) {
          curlData += line;
          console.log(`4 Line from file: ${lcnt}  ${line}`);
        } */
      });
      console.log("After Line:   " + curlData);

      rl.on('close', function () {
        resolve({
          data: curlData,
        });
      });
      //await events.once(rl, 'close');
      /* console.log('Reading file line by line with readline done.');
      const used = process.memoryUsage().heapUsed / 1024 / 1024;
      console.log(`The script uses approximately ${Math.round(used * 100) / 100} MB`); */
    } catch (error) {
      reject(error);
    }
  })
}



exports.processLineByLine = processLineByLine;
