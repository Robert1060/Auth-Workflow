const mongoose = require('mongoose')

const tokenSchema = new mongoose.Schema({
    refreshToken:{
        type:String,
        required:true
    },
    ip:{
        type:String,
        required:true
    },
    userAgent:{
        type:String,
        required:true
    },
    isValid:{
        type:Boolean,
        default:true
    },
    user:{
        type:mongoose.Types.ObjectId,
        ref:'User',
        required:true
    }
},{timestamps:true})


module.exports = new mongoose.model('Token',tokenSchema)