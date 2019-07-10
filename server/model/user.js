var Sequelize=require("sequelize")
var db = require("../server")




//user model(should be same as the ones in the db)
//exporting the model to be used througout the app
//db.sequelize is used to give sequelize functionalities for our db (.define)
module.exports = db.sequelize.define(
  'user',
  {
    id: {
      //caharacteristics of the variable
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    username:{
       //caharacteristics of the variable
      type: Sequelize.STRING
    },
    first_name: {
       //caharacteristics of the variable
      type: Sequelize.STRING
    },
    last_name: {
       //caharacteristics of the variable
      type: Sequelize.STRING
    },
    email: {
       //caharacteristics of the variable
      type: Sequelize.STRING
    },
    password: {
       //caharacteristics of the variable
      type: Sequelize.STRING
    },
    created: {
       //caharacteristics of the variable
      type: Sequelize.DATE,
      defaultValue: Sequelize.NOW
    }
  },
  {
    //used for setting createdAt and updatedAt to false
    //by default it is true
    timestamps: false
  }
)

  


