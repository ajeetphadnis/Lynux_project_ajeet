const upFile = require("./fileuploadJS");
const fs =  require("fs");
const express = require('express');
const bodyParser = require("body-parser");
var formidable = require('formidable');
const { userInfo } = require("os");
const router = express.Router();
const app = express();
const port = 3000;
app.set("view options", {layout: false});
app.use(express.static(__dirname + './'));
//Here we are configuring express to use body-parser as middle-ware.
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(bodyParser.json());
app.engine('html', require('ejs').renderFile);
var urlencoded = bodyParser.urlencoded({extended:true});
// add router in the Express app.
app.use("/", router);

app.get('/', function(req, res) {
    res.render('fileuploadJS.html');
});


app.post('/uploadJS',  (req,res,next) => {
	console.log("uploadJS: called ");
	var form = new formidable.IncomingForm();
	console.log("uploadJS:002 ");
	form.keepExtensions = true;
	console.log("uploadJS:003 ");
    form.parse(req, function(err, fields, files) { 
    	var tempFilePath = files.file['path'],
        userFileName  = files.file['name'],
        contentType   = files.file['type'];
		console.log("uploadJS:004  " + tempFilePath + "   "  + userFileName + "    " + contentType);
		// then read your file with fs 
		// you can also move your file to another location with fs 
		// by default file will be place to tempFilePath
		console.log("uploadJS:005 ");
		//fs.readFile( tempFilePath, function(err, file_buffer){
		//	if(!err) {
		//		console.log("file:  " ); //+ file_buffer.toString());
		//	}
		//});
	});

    // do what you want to do with your file 
	//console.log("uploadJS:    " + res.json({requestBody: req.body}));
		try {
			if(!req.body) {
				console.log("uploadJS: no files " );		
				res.send({
					status: false,
					message: 'No file uploaded'
				});
			} else {
				//res.json({requestBody: req.body});
				console.log("file upload:001   " + req.files.avatar);
				// use the name of the input field (i.e. "avatar") 
				// to retrieve the uploaded file
				var avatar = req.files.avatar;
				console.log("file upload:002   " + avtar);
				// use the mv() method to place the file in 
				// upload directory (i.e. "uploads")
				avatar.mv('./uploads/' + avatar.name);
	
				//send response
				res.send({
					status: true,
					message: 'File is uploaded'
				});
			}
		} catch (err) {
			res.status(500).send(err);
		}
	});
	
	

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})



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
exports.getUploadFileName = getUploadFileName;