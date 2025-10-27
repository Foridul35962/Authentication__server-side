import jwt from "jsonwebtoken";
import asyncHandler from '../utils/asyncHandler.js'
import ApiErrors from "../utils/ApiError.js";
import { User } from "../models/users.models.js";
import generateAccessAndRefreshToken from "../utils/token.js";

const verifyJwt = asyncHandler(async (req, res, next) => {
    let incommingAccessToken = req.cookies?.accessToken
    const incommingRefreshToken = req.cookies?.refreshToken

    // If access token missing
    if (!incommingAccessToken) {
        if (!incommingRefreshToken) {
            throw new ApiErrors(400, "access token is not found")
        }

        // Verify refresh token
        const decodedRefreshToken = jwt.verify(incommingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        const incommingUser = await User.findById(decodedRefreshToken._id)
        if (!incommingUser || incommingRefreshToken !== incommingUser.refreshToken) {
            throw new ApiErrors(400, "Invalid refresh token")
        }

        // Generate new access token only
        const { accessToken } = await generateAccessAndRefreshToken(decodedRefreshToken._id, true)
        const option = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Strict",
            maxAge: 15 * 60 * 1000
        }

        // Set new access token in cookie
        res.cookie('accessToken', accessToken, option)

        // Update variable for below verification
        incommingAccessToken = accessToken
    }

    const decodedJwt = await jwt.verify(incommingAccessToken, process.env.ACCESS_TOKEN_SECRET)
    if (!decodedJwt) {
        throw new ApiErrors(400, 'access token is not valid')
    }

    const user = await User.findById(decodedJwt._id).select("-password -refreshToken")

    if (!user) {
        throw new ApiErrors(400, 'user not found from token')
    }

    req.user = user
    next()
})

export default verifyJwt