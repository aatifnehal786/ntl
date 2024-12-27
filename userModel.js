const mongoose = require('mongoose')

const userSchema = mongoose.Schema({
    name:{
        type:String,
        required:[true,"Name is Mandatory"]
    },
    email:{
        type:String,
        required:[true,"Email is Mandatory"]
    },
    password:{
        type:String,
        required:[true,"password is Mandatory"]
    },
    age:{
        type:Number,
        required:[true,"Age is Mandatory"],
        min: 12
    },
    resetToken: {
        token: { type: String },
        expires: { type: Date },
    }
},{timestamps:true})

const userModel = mongoose.model("users",userSchema)

module.exports = userModel;