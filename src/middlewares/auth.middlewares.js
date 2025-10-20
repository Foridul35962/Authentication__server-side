import jwt from "jsonwebtoken";
import asyncHandler from '../utils/asyncHandler.js'
import ApiErrors from "../utils/ApiError.js";
import { User } from "../models/users.models.js";

const verifyJwt = asyncHandler(async (req, res, next) => {
    const imcommingAccessToken = req.cookies?.accessToken
    if (!imcommingAccessToken) {
        throw new ApiErrors(400, "access token is not found")
    }

    const decodedJwt = await jwt.verify(imcommingAccessToken, process.env.ACCESS_TOKEN_SECRET)
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