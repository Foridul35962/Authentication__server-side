import mongoose from "mongoose";

const tempUserSchema = new mongoose.Schema({
    userName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    otpExpired: {
        type: Date,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 86400  // 1 day = 86400 seconds
    } 
})

export const TempUser = mongoose.model('tempuser', tempUserSchema)