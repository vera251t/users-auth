const EmailCode = require("./EmailCode");
const User = require("./User");

//EmailCode -> userId
User.hasOne(EmailCode) //userId
EmailCode.belongsTo(User)