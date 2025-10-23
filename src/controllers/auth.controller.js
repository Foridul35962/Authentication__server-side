import { User } from "../models/users.models.js";
import ApiErrors from "../utils/ApiError.js";
import asyncHandler from "../utils/asyncHandler.js";
import { check, validationResult } from 'express-validator'
import ApiResponse from "../utils/ApiResponse.js";
import generateAccessAndRefreshToken from "../utils/token.js";
import transport from "../config/nodemailer.js";
import { TempUser } from "../models/tempUser.models.js";
import { generatePasswordResetMail, generateVerificationMail } from "../utils/verificationMail.js";


export const registerUser = [
    check('email')
        .isEmail()
        .withMessage('Enter a valid email')
        .normalizeEmail(),
    check('password')
        .trim()
        .isLength({ min: 8 })
        .withMessage('password must be 8 character')
        .matches(/[a-zA-Z]/)
        .withMessage('Password must be has one alphabet')
        .matches(/[0-9]/)
        .withMessage('Password must be has one number'),
    check('confirm_password')
        .trim()
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new ApiErrors(400, "password not match")
            }
            return true
        }),

    asyncHandler(async (req, res) => {
        const error = validationResult(req)
        if (!error.isEmpty()) {
            throw new ApiErrors(400, 'insert wrong value', error.array())
        }

        const { userName, email, password } = req.body
        if (!userName || !email || !password) {
            throw new ApiErrors(400, "All value are required")
        }

        const isEmailUsed = await User.findOne({ email })
        if (isEmailUsed) {
            throw new ApiErrors(400, 'Email is already used')
        }

        //sending mail
        const otp = String(Math.floor(100000 + Math.random() * 900000))
        const otpExpired = Date.now() + 1000 * 60 * 5      //5 minutes
        const mailOptions = generateVerificationMail(email, otp)

        //save in temporary user
        await TempUser.findOneAndUpdate(
            {email},
            {userName, password, otp, otpExpired, createdAt: Date.now()},
            {upsert: true, new: true}
        )

        try {
            await transport.sendMail(mailOptions)
        } catch (error) {
            throw new ApiErrors(400, "otp send failed")
        }

        return res
            .status(200)
            .json(
                new ApiResponse(200, {}, 'otp send successfully')
            )
    })
]

export const verifyEmail = asyncHandler(async (req, res) => {
    const { otp, email } = req.body

    if (!email) {
        throw new ApiErrors(400, "email is required")
    }

    const temp = await TempUser.findOne({email})
    if (!temp) {
        throw new ApiErrors(404, "temp user not found")
    }

    if (otp === '' || otp !== temp.otp) {
        throw new ApiErrors(400, 'otp is not matched')
    }

    if (temp.otpExpired.getTime() < Date.now()) {
        throw new ApiErrors(400, 'otp is expired')
    }

    const user = await User.create({
        userName: temp.userName,
        email: temp.email,
        password: temp.password
    })

    await TempUser.findByIdAndDelete(temp._id)

    const userData = user.toObject()
    delete userData.password

    return res
        .status(200)
        .json(
            new ApiResponse(200, userData, "user register successfully")
        )
})

export const userLoggedIn = asyncHandler(async (req, res) => {
    const { email, password } = req.body
    if (!email || !password) {
        throw new ApiErrors(400, 'All fields are required')
    }

    const user = await User.findOne({ email })
    if (!user) {
        throw new ApiErrors(400, "user is not found")
    }

    const isPassValid = await user.isPasswordCorrect(password)

    if (!isPassValid) {
        throw new ApiErrors(400, 'password is incorrect')
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

    const accessOptions = {
        httpOnly: true,
        // secure: true,
        maxAge: 15 * 60 * 1000
    }

    const refreshOptions = {
        httpOnly: true,
        // secure: true,
        maxAge: 24 * 60 * 60 * 1000 * 7
    }

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    return res
        .status(200)
        .cookie('accessToken', accessToken, accessOptions)
        .cookie('refreshToken', refreshToken, refreshOptions)
        .json(
            new ApiResponse(200, loggedInUser, "User loggedIn successfully")
        )
})

export const userLoggedOut = asyncHandler(async (req, res) => {
    if (!req.user?._id) {
        throw new ApiErrors(401, "User not authenticated")
    }

    await User.findByIdAndUpdate(
        req.user._id,
        {
            refreshToken: undefined
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true,
        sameSite: "strict"
    }

    return res
        .status(200)
        .clearCookie('accessToken', options)
        .clearCookie('refreshToken', options)
        .json(
            new ApiResponse(200, {}, 'user logged out successfully')
        )
})

export const sendPassResetOtp = asyncHandler(async (req, res) => {
    const { email } = req.body
    if (!email) {
        throw new ApiErrors(400, "Email is required")
    }

    const user = await User.findOne({ email })
    if (!user) {
        throw new ApiErrors(404, "user not found")
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000))
    const otpExpired = Date.now() + 1000 * 60 * 5      //5 minutes
    
    await TempUser.findOneAndUpdate(
        {email},
        {otp, otpExpired, createdAt: Date.now()},
        {upsert: true, new : true, validateBeforeSave: false}
    )

    const mailOptions = generatePasswordResetMail(email, otp)

    try {
        await transport.sendMail(mailOptions)
    } catch (error) {
        throw new ApiErrors(400, "otp send failed")
    }

    return res
        .status(200)
        .json(
            new ApiResponse(200, {}, 'Otp sent successfully')
        )
})

export const checkPassOtp = asyncHandler(async (req, res)=>{
    const {otp, email} = req.body
    if (!email) {
        throw new ApiErrors(400, 'email is required')
    }

    const temp = await TempUser.findOne({email})
    if (!temp) {
        throw new ApiErrors(404, 'Temp User is not found')
    }

    if (otp === '' || otp !== temp.otp) {
        throw new ApiErrors(400, "Otp is not matched")
    }

    if (temp.otpExpired < Date.now()) {
        throw new ApiErrors(400, 'otp is expired')
    }

    await TempUser.findByIdAndDelete(temp._id)

    return res
        .status(200)
        .json(
            new ApiResponse(200, {}, 'Reset Password Otp is matched')
        )
})

export const resetPass = [
    check('password')
        .trim()
        .isLength({ min: 8 })
        .withMessage('password must be has 8 character')
        .matches(/[0-9]/)
        .withMessage('password must has a number')
        .matches(/[a-zA-Z]/)
        .withMessage('password must has a alphabet'),
    check('confirm_password')
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new ApiErrors(400, 'password not matched')
            }
            return true
        }),

    asyncHandler(async (req, res) => {
        const { email, password } = req.body

        const error = validationResult(req)

        if (!error.isEmpty()) {
            throw new ApiErrors(400, 'entered wrong value', error.array())
        }

        if (!email || !password) {
            throw new ApiErrors(400, "all field are required")
        }

        const user = await User.findOne({ email })

        if (!user) {
            throw new ApiErrors(400, "user not found")
        }

        user.password = password
        await user.save({ validateBeforeSave: false })

        return res
            .status(200)
            .json(
                new ApiResponse(200, {}, 'password reset successfully')
            )
    })
]