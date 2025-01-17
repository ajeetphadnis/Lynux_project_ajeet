// call all the required packages
// https://code.tutsplus.com/tutorials/file-upload-with-multer-in-node--cms-32088
const express = require('express');
const bodyParser= require('body-parser');
const multer = require('multer');

 
const app = express();
app.use(bodyParser.urlencoded({extended: true}));

//SET STORAGE
var storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads')
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now())
  }
});
 
var upload = multer({ storage: storage });

//ROUTES WILL GO HERE
//ROUTES
app.get('/',function(req,res){
  res.sendFile(__dirname + '/multerUpload.html');
 
});

app.post('/uploadfile', upload.single('myFile'), (req, res, next) => {
	  const file = req.file
	  if (!file) {
	    const error = new Error('Please upload a file')
	    error.httpStatusCode = 400
	    return next(error)
	  }
	    res.send(file)
	  
	});
 
app.listen(3000, () => console.log('Server started on port 3000'));