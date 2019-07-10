//Sequelize is an npm that manages connections and functions with data base
var  Sequelize = require('sequelize')
//setting the db as a global non restrictive variable
const db = {}
//requiring sequelize in sequelize constant 
//starting the connection with mysql db , with db name , username , pass , host , and program
//can be graphql , any sequel dependant db
const sequelize = new Sequelize('users', 'root', '', {
  host: 'localhost',
  dialect: 'mysql',
  
//number of connections that can be made
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  },
})

//performing db connection using sequelize
db.sequelize = sequelize
db.Sequelize = Sequelize
//exporting the db to be used throughout the app
module.exports = db



  