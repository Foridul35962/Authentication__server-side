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

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")
    
    const accessOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
    }
    
    const refreshOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 * 10
    }

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