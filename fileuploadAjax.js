const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');app.use(express.static(path.join(__dirname, '/public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.get('/', (req, res)=>{
    console.log("Get called");
    res.sendFile( __dirname + "/" + "fileuploadAjax.html" );
 })
app.post('/', (req, res) => {
  const user = {
    name: req.body.name,
    email: req.body.email,
    mobile: req.body.mobile
  }
  console.log(user)
  //res.send(user)
  //res.send(req.body);
  //res.redirect("/");
  res.render('fileuploadAjax.html', {user: user});
})

app.listen(3000)