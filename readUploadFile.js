var fs =  require("fs");
var path = require("path"); 
const readline = require('readline');
//var FileReader = require('filereader')





function getUploadFileName(dir, strtStr, endStr) {
		//const dir = '/Users/flavio/folder'
		const files = fs.readdirSync(dir);
		
		for (const file of files) {
			if (file.startsWith(strtStr)) {
				console.log(file);
				return file;
			}	  
		}
	};



	function getCertRemoveNewLine() {
		var folderName = 'E:/App2/App2/utes_apps/com.utes.auth.protocol.exchange_new/ecdsa_keycerts/ecdsaKeyCerts/new1.txt';
		//path.join('/ecdsa_keycerts/ecdsaKeyCerts', 'users', name, 'notes.txt');
		var str = `Certificate:\n    Data:\n        Version: 3 (0x2)\n        Serial Number:\n            54:74:2c:e1:5f:ac:f1:4f:6a:c8:5f:76:7d:32:de:44:be:df:54:f0\n        Signature Algorithm: ecdsa-with-SHA256\n        Issuer: CN = atul, C = na, O = Atul.Verma, ST = Atul.Verma, L = na, OU = Atul.Verma, emailAddress = atul.verma@gmail.com\n        Validity\n            Not Before: Dec 22 05:31:23 2022 GMT\n            Not After : Dec 21 05:31:23 2024 GMT\n        Subject: CN = atul, C = na, O = Atul.Verma, ST = Atul.Verma, L = na, OU = Atul.Verma, emailAddress = atul.verma@gmail.com\n        Subject Public Key Info:\n            Public Key Algorithm: id-ecPublicKey\n                Public-Key: (256 bit)\n                pub:\n                    04:e2:e3:cc:88:f3:60:48:bd:e3:31:4a:4d:46:a8:\n                    f9:19:d4:61:32:03:14:d3:6e:63:2b:56:46:e2:aa:\n                    6b:40:9c:8c:63:51:37:27:14:b3:c6:7a:81:44:ab:\n                    43:b2:92:70:cd:b4:af:e9:7a:46:91:cf:8b:e1:7d:\n                    e2:06:d0:39:fb\n                ASN1 OID: prime256v1\n                NIST CURVE: P-256\n        X509v3 extensions:\n            X509v3 Subject Key Identifier: \n                34:85:13:B7:AF:8C:81:AB:91:A1:8E:6A:C3:F9:4B:BC:56:75:8A:3E\n            X509v3 Authority Key Identifier: \n                keyid:34:85:13:B7:AF:8C:81:AB:91:A1:8E:6A:C3:F9:4B:BC:56:75:8A:3E\n\n            X509v3 Basic Constraints: critical\n                CA:TRUE\n            X509v3 Subject Alternative Name: \n                DNS:utes.phadnis.com\n            X509v3 Certificate Policies: \n                Policy: 1.2.3.4\n\n    Signature Algorithm: ecdsa-with-SHA256\n         30:46:02:21:00:f1:e4:d1:eb:b8:f7:81:5e:ea:f2:db:6f:a4:\n         fc:aa:1d:19:76:e1:e2:40:83:af:21:3e:7d:2f:34:fc:7c:36:\n         0d:02:21:00:a0:fa:ac:1f:7e:8c:23:2d:c2:92:51:24:7c:2a:\n         91:7d:07:0e:39:8a:75:6f:a3:5e:98:3a:d8:c3:8c:57:eb:87\n-----BEGIN CERTIFICATE-----\nMIICozCCAkigAwIBAgIUVHQs4V+s8U9qyF92fTLeRL7fVPAwCgYIKoZIzj0EAwIw\ngY0xDTALBgNVBAMMBGF0dWwxCzAJBgNVBAYTAm5hMRMwEQYDVQQKDApBdHVsLlZl\ncm1hMRMwEQYDVQQIDApBdHVsLlZlcm1hMQswCQYDVQQHDAJuYTETMBEGA1UECwwK\nQXR1bC5WZXJtYTEjMCEGCSqGSIb3DQEJARYUYXR1bC52ZXJtYUBnbWFpbC5jb20w\nHhcNMjIxMjIyMDUzMTIzWhcNMjQxMjIxMDUzMTIzWjCBjTENMAsGA1UEAwwEYXR1\nbDELMAkGA1UEBhMCbmExEzARBgNVBAoMCkF0dWwuVmVybWExEzARBgNVBAgMCkF0\ndWwuVmVybWExCzAJBgNVBAcMAm5hMRMwEQYDVQQLDApBdHVsLlZlcm1hMSMwIQYJ\nKoZIhvcNAQkBFhRhdHVsLnZlcm1hQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABOLjzIjzYEi94zFKTUao+RnUYTIDFNNuYytWRuKqa0CcjGNRNycU\ns8Z6gUSrQ7KScM20r+l6RpHPi+F94gbQOfujgYMwgYAwHQYDVR0OBBYEFDSFE7ev\njIGrkaGOasP5S7xWdYo+MB8GA1UdIwQYMBaAFDSFE7evjIGrkaGOasP5S7xWdYo+\nMA8GA1UdEwEB/wQFMAMBAf8wGwYDVR0RBBQwEoIQdXRlcy5waGFkbmlzLmNvbTAQ\nBgNVHSAECTAHMAUGAyoDBDAKBggqhkjOPQQDAgNJADBGAiEA8eTR67j3gV7q8ttv\npPyqHRl24eJAg68hPn0vNPx8Ng0CIQCg+qwffowjLcKSUSR8KpF9Bw45inVvo16Y\nOtjDjFfrhw==\n-----END CERTIFICATE-----\n`;
		/*try {
			var content = fs.readFileSync('new.txt', 'utf-8');
			content = content.replace(/(?:\r\n|\r|\n)/g, '\r\n');
            console.log(content);		
		} catch (err) {
		  console.error(err);
		}
		var finalStr = '';
		fs.readFile('new.txt', function(err, data) {
			if(err) throw err;
			var array = data.toString().split("\n");
			for(i in array) {
				finalStr = array[i].toString().split('\\n');
				finalStr.toString().replace('\'', '');
				console.log(finalStr);
			}
		});*/

		//var content = fs.readFileSync('new.txt', {encoding: 'utf8'});
		//content = content.toString().replace(/(?:\r\n|\r|\n)/g, '');
		//var array = require("fs").readFileSync('new.txt').toString().split("\\n");
		//console.log(array);
		fs.readFileSync('new.txt', 'utf-8').split(/\r?\n/).forEach(function(line){
			line = line.replace(/(?:\r\n|\r|\n)/g, '');
			console.log(line);
		});
	}

	async function myFileReader() {
		const file = await fs.open('new.txt');
		for await (const line of file.readLines()) {
			arr.push(line);
		}
		console.log(arr)
	}


	async function readFileLine() {
		fs.readFile('new.txt', 'utf-8', (err, file) => {
			const lines = file.split('\n');
			var line = '';
			for (line of lines)
				line = line.toString();
				line = line.replace(/(?:\r\n|\r|\n)/g, '');
			  console.log(line)
		  });
	}


	async function processLineByLine() {
		var rd = readline.createInterface({
			input: fs.createReadStream('new.txt'),
			output: process.stdout,
			console: false
		});
		var result = '';
		rd.on('line', function(line) {
			result = result+line;
			//console.log(line);
		});
		console.log("content:  " + result);
	  }


	  async function readFile2String() {
		var ecdsaStr = fs.readFileSync('new.txt', 'utf8');
		/*var str = fStr.toString();
		str = str.replace(/(?:\r\n|\r|\n)/g, '\r\n');
		console.log(fStr.toString());*/
		//ecdsaStr = ecdsaStr.replace(/(?:\\r\\n)|\n/g, '\r\n').trim();
		ecdsaStr = ecdsaStr.replace(/(?:\\r\\n)|\n/g, '').trim();
		ecdsaStr = ecdsaStr.replace( /[\"\\\"]+/gm, '\r\n' ).trim();//
		ecdsaStr = ecdsaStr.replace(/^[^\n]/gm, "");
		ecdsaStr = 'C'+ecdsaStr;
		console.log("Result:  " + ecdsaStr);
		/*while( ecdsaStr.charAt( 0 ) === 'n' )
			ecdsaStr = ecdsaStr.slice( 1 );*/
		//console.log("Result:  " + 'C'+ecdsaStr);
		/*if (ecdsaStr.charAt(0) === '"' && ecdsaStr.charAt(ecdsaStr.length -1) === '"') {
				ecdsaStr = ecdsaStr.substr(1,str.length -2);
				console.log(ecdsaStr.substr(1,str.length -2));
		}*/
	}


	function readFileAsString(filename) {
		var files = this.files;
		var reader = new FileReader();
		reader.onload = function(event) {
			console.log('File content:', event.target.result);
		};
		reader.readAsText(filename);
	}



exports.getUploadFileName = getUploadFileName;
//getCertRemoveNewLine();
//myFileReader();
//readFileLine();
//processLineByLine();
readFile2String();
//readFileAsString('new.txt');