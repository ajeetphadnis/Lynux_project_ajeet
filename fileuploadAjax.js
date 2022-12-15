/**
 * 
 */

const express = require('express');
const fileUpload = require('express-fileupload');
const fs = require('fs');
const path = require('path');
const formidable = require("formidable");

const app = express();

user = {
	uid: '',
	pass: '',
	serv: '',
	srctxt: '',
	destxt: '',
	jwksets: '',
	oprf: '',
	oprt: '',
	Timestamp: '',
	target: '',
	filetype: '',
	Content: '',
	keyInfo: ''
};

//ROUTES
app.get('/',function(req,res){
  res.sendFile(__dirname + '/fileuploadAjax.html');
 
});



// files attrs: {"upload_file":{"size":2844,"filepath":"uploads\\43428fb2470119a305d5f3a00","newFilename":"43428fb2470119a305d5f3a00","mimetype":"text/xml","mtime":"
//	2022-02-26T15:21:50.122Z","originalFilename":"NDCAPXMLO_0009192838-R_20171013-171903.xml"}}


app.post('/upload', (req, res, next) => {
	const uploadFolder = path.join("./uploads");

	const form = formidable({ multiples: true });
	form.multiples = true;
	form.maxFileSize = 50 * 1024 * 1024; // 5MB
	form.uploadDir = uploadFolder;
	form.encoding = 'utf-8';
	var pars;
	var fil;
    var formfields = new Promise(function (resolve, reject) {
        form.parse(req, function (err, fields, files) {
            if (err) {
                reject(err);
                return;
            }
            console.log("within form.parse method, subject field of fields object is: " + fields.uid);
            resolve(fields);
            resolve(files);
            pars = JSON.parse(JSON.stringify(fields));
            fil = JSON.parse(JSON.stringify(files));
            //fl = JSON.parse(fil);
            var jfpath = JSON.stringify(fil.upload_file.filepath);
            jfpath = jfpath.replace(/[\[\]'"]/gi, '');
            console.log("POST:   " + jfpath);
            console.log("POST:   " + JSON.stringify(fil.upload_file.newFilename));
            fs.readFile(jfpath, "utf8", (err, data) => {
	            if (err) throw err;
	            user.Content = data.toString();
	            console.log("Read Uploadedfile:   " + user.Content);
	        });
            const filePath = path.join(__dirname, jfpath);
            console.log("path:  " + filePath);
        }); // form.parse
    });

    //console.log("POST:   " + JSON.stringify(fil.upload_file.filepath));
    //console.log("POST:   " + fil.newFilename);
    res.end();
});


//app.post('/upload', (req, res, next) => {
//	const uploadFolder = path.join(__dirname, "uploads");
//	const form = formidable({ multiples: true });
//	form.multiples = true;
//	form.maxFileSize = 50 * 1024 * 1024; // 5MB
//	form.uploadDir = uploadFolder;
//	var pars;
//	var fil;
//	form.parse(req, (err, fields, files) => {    
//		fil = JSON.parse(JSON.stringify(files));
//		console.log("POST:   " + JSON.stringify(files));
//	    console.log("POST:   " + fil.upload_file.filepath);
//	    console.log("POST:   " + fil.upload_file.newFilename);
//	    pars = JSON.parse(JSON.stringify(fields));
//	    console.log("POSTfields:   " + pars.uid);
//	});
//    res.end();
//});

app.listen(3000, () => console.log('Your app listening on port 3000'));