/**
 * 
 */

 const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');app.use(express.static(path.join(__dirname, '/public')));
app.use(bodyParser.urlencoded({ extended: true }));
    

 
 //ROUTES
 app.get('/',function(req,res){
    console.log("Get:");
     res.sendFile(path.join(__dirname,  'views/com.utes.protocol.exchange.html')); 
 });
 
 app.post('/two', (request,response, next)  => {
    //code to perform particular action.
    //To access POST variable use req.body()methods.
    console.log(request.body);
    response.end();
    });
 
 // files attrs: {"upload_file":{"size":2844,"filepath":"uploads\\43428fb2470119a305d5f3a00","newFilename":"43428fb2470119a305d5f3a00","mimetype":"text/xml","mtime":"
 //	2022-02-26T15:21:50.122Z","originalFilename":"NDCAPXMLO_0009192838-R_20171013-171903.xml"}}
 
 
 app.post('/nothing', function(req, res, next) { 
     //Do some req verification stuff here
     console.log("POST: reqbody:  " );
     const uploadFolder = path.join("./uploads");
     console.log("reqbody:  " + JSON.stringify(req.body));
     var fileContent;
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
             user.uid = fields.uid;
             console.log("Field Target: " + fields.target);
             user.target = fields.target
             console.log("Field file_type: " + fields.filetype);
             user.filetype = fields.filetype;
             console.log("Field file: " + fields.upload_file);
 
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
                 //fileContent = data.toString();
                 console.log("Read Uploadedfile:   " + user.Content);
                 user.uid = "yogesh";
                 user.oprf = "non";
             });
 
 
         });
     });
     //If req verfiication passes
     var servResp = {};
     servResp.success = true;
     servResp.redirect = true;
     servResp.redirectURL = "http://localhost:3000/";
     res.render('com.utes.protocol.exchange.html',  
                     { user: user
                     });
     //res.sendFile('fileuploadAjaxUpdate.html', { root: __dirname , user: user}); 
     //res.redirect('/',  { user: user}); 
 });
 
 
 
 
 app.post('/', (req, res, next) => {
     const uploadFolder = path.join("./uploads");
     console.log("reqbody:  " + JSON.stringify(req.body));
     var fileContent;
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
             user.uid = fields.uid;
             console.log("Field Target: " + fields.target);
             user.target = fields.target
             console.log("Field file_type: " + fields.filetype);
             user.filetype = fields.filetype;
             console.log("Field file: " + fields.upload_file);
 
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
                 //fileContent = data.toString();
                 console.log("Read Uploadedfile:   " + user.Content);
                 user.uid = "yogesh";
                 user.oprf = "non";
             });
             const filePath = path.join(__dirname, jfpath);
             console.log("path:  " + filePath);
             //user.uid = "ajeeet";
             user.Content = fileContent;
             console.log("REQ:BODY:  " + JSON.stringify(req.body));
             //res.setHeader('Content-type','multipart/form-data');
             //res.status(200).send({ user: user });
             //res.send(JSON.stringify(req.body, { user: user }));
             //res.sendFile(__dirname + '/fileuploadAjaxUpdate.html', { formD: JSON.stringify(req.body )});
             //res.status(200).send(req.body);
             //res.header("Access-Control-Allow-Origin", "*");
             //res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
             //res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
 
             res.render('com.utes.protocol.exchange.html', {user: user});
             //res.redirect('/');
             //res.end();
             //res.json({ user: user });
         }); // form.parse
     });
 
     //console.log("POST:   " + JSON.stringify(fil.upload_file.filepath));
     //console.log("POST:   " + fil.newFilename);
     //res.end();
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