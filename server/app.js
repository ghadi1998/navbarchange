//the main framework , express
var express = require('express');
//path , used for joining pathes
var path = require('path');
//cross origin resource sharing 
var cors= require('cors')
//body parser used to take data from forms , to be used later on
var bodyParser=require("body-parser");
//for security reasons , http security(not https)
var helmet= require('helmet')
//for parsing tokens and session cookies
var cookieParser= require('cookie-parser')
//assigning express functionaities as a global variable
const app = express()
//assigning cors functionaities as a global variable
app.use(cors())



//headers that will be sent to the browser
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Methods', ['PATCH', 'POST', 'GET', 'DELETE', 'PUT']);
  res.setHeader('Access-Control-Allow-Headers' , '*')
  res.setHeader('Access-Control-Expose-Headers' ,'content-type')
  next();
});

//body parser for form data
app.use(bodyParser.json())
app.use(bodyParser.json({ type: 'application/json' }))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cookieParser())
// secure apps by setting various HTTP headers
app.use(helmet())
// enable CORS - Cross Origin Resource Sharing
 app.options('*', cors()); 


//fetching index from react
app.use(express.static('./build/'));
app.use(express.static(path.join(__dirname, './client/build')));
app.get('*', (req, res) => {
  res.send(express.static(path.join(__dirname, './client/build/index.html')))  ;
});

//giving the functionalities of users.js to a variable users to be used later on
var Users = require('./routes/Users')
//using the functions assigned for users
app.use('/users', Users)

 
 



  
//exporting the app file 
 module.exports = app


 //note , the app is using a build script , which meanse that all of the pages and functions are rendered 
 //in the ./bin/www , for compiling reasons , security , cross origin sharing 
 //for not compiling to es6 on the client side
 //didnot use pure webpack for complication reasons 
 //using hot reloaders , react , redux , minified js scripts in build directory