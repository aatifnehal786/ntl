const mongoose = require('mongoose')
const crtpto = require('crypto')
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
   
    otp: { type: String },
    otpExpires: { type: Date },
    isVerified: { type: Boolean, default: false }
    
},{timestamps:true})

userSchema.methods.generateOtp = function () {
    const otp = crypto.randomInt(100000, 999999).toString(); // Generate a 6-digit OTP
    this.otp = otp;
    this.otpExpires = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes
    return otp;
};

const userModel = mongoose.model("users",userSchema)

module.exports = userModel;
