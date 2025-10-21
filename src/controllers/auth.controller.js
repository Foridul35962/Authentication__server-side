import { User } from "../models/users.models.js";
import ApiErrors from "../utils/ApiError.js";
import asyncHandler from "../utils/asyncHandler.js";
import { check, validationResult } from 'express-validator'
import ApiResponse from "../utils/ApiResponse.js";
import generateAccessAndRefreshToken from "../utils/token.js";
import transport from "../config/nodemailer.js";


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

        const user = await User.create({
            userName, email, password
        })
        const userData = user.toObject()
        delete userData.password

        //sending mail
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to my Authentication Project',
            text: `Welcome to My website. Your account has been created with email id: ${email}`
        }

        await transport.sendMail(mailOptions)

        return res
            .status(200)
            .json(
                new ApiResponse(200, userData, 'user registration is successfully')
            )
    })
]

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

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    return res
        .status(200)
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

export const sendVerifyOtp = asyncHandler(async (req, res) => {
    const { userId } = req.body
    try {
        const user = await User.findById(userId)
        const otp = String(Math.floor(100000 + Math.random() * 900000))
        user.verifyOtp = otp
        user.verifyOtpExpired = Date.now() + 1000 * 60 * 5      //5 minutes
        await user.save({ validateBeforeSave: false })
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Welcome to my Authentication Project',
            text: `Welcome to My website. Your otp is ${otp}. please verify your account using This OTP`
        }

        try {
            await transport.sendMail(mailOptions)
        } catch (error) {
            throw new ApiErrors(400, "otp send failed")
        }

        return res
            .status(200)
            .json(
                new ApiResponse(200, {}, "varification Otp is sended successfully")
            )
    } catch (error) {
        throw new ApiErrors(400, "verification otp sended failed")
    }
})

export const verifyEmail = asyncHandler(async (req, res) => {
    const { userId, otp } = req.body
    if (!userId) {
        throw new ApiErrors(400, "user Id is required")
    }
    const user = await User.findById(userId)

    if (!user) {
        throw new ApiErrors(400, "user not found")
    }

    if (otp === '' || user.verifyOtp !== otp) {
        await user.save({ validateBeforeSave: false })
        throw new ApiErrors(400, "Otp is not matched")
    }

    if (user.verifyOtpExpired < Date.now()) {
        user.verifyOtp = ''
        user.verifyOtpExpired = 0
        await user.save({ validateBeforeSave: false })
        throw new ApiErrors(400, "OTP is expired")
    }

    user.verifyOtp = ''
    user.verifyOtpExpired = 0
    await user.save({ validateBeforeSave: false })

    const verifiedUser = await User.findById(user._id).select("-password -refreshToken -verifyOtp")

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)

    const accessOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000
    }

    const refreshOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 * 7
    }

    return res
        .status(200)
        .cookie('accessToken', accessToken, accessOptions)
        .cookie('refreshToken', refreshToken, refreshOptions)
        .json(
            new ApiResponse(200, verifiedUser, "user is verified successfully")
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
    user.verifyOtp = otp
    user.verifyOtpExpired = Date.now() + 1000 * 60 * 5      //5 minutes
    await user.save({ validateBeforeSave: false })

    const mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject: 'Reset Password',
        text: `Hello ${user.name || ''}, You requested a password reset for your account. Your one-time OTP is: ${otp}. This OTP will expire in 5 minutes. If you didn’t request this, please ignore this email.`
    }

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
        const {email, password, otp} = req.body

        const error = validationResult(req)
        
        if (!error.isEmpty()) {
            throw new ApiErrors(400, 'entered wrong value', error.array())
        }

        if (!email || !password) {
            throw new ApiErrors(400, "all value are required")
        }

        const user = await User.findOne({email})

        if (!user) {
            throw new ApiErrors(400, "user not found")
        }

        if (otp === '' || otp !== user.verifyOtp) {
            throw new ApiErrors(400, 'otp is not matched')
        }

        if (user.verifyOtpExpired<Date.now()) {
            throw new ApiErrors(400, 'otp is expired')
        }
        
        user.verifyOtp = ''
        user.verifyOtpExpired = 0
        user.password = password
        await user.save({validateBeforeSave: false})

        return res
            .status(200)
            .json(
                new ApiResponse(200, {}, 'password reset successfully')
            )
    })
]