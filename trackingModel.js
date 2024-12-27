const mongoose = require('mongoose')

const trackingSchema = mongoose.Schema(
    {
        user:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"users",
            required:true
        },
        food:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"foods",
            required:true
        },
        details:{
           
            calories:Number,
            protein:Number,
            carbohydrates:Number,
            fat:Number,
            fiber:Number,
           
        },
        eatendate:{
            type:String,
            default: new Date().toLocaleDateString()
        },
        quantity:{
            type:Number,
            min:1,
            required:true
        }
    },{timestamps:true}
)

const trackingModel = mongoose.model("trackings",trackingSchema)

module.exports = trackingModel;