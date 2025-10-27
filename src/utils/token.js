import { User } from "../models/users.models.js";
import ApiErrors from "./ApiError.js";

const generateAccessAndRefreshToken = async (userId, isOnlyAccessToken = false)=>{
    if (!userId) {
        throw new ApiErrors(400, 'user id is required')
    }

    try {
        const user = await User.findById(userId)
        if (!user) {
            throw new ApiErrors(404, 'user not found')
        }
        const accessToken = await user.generateAccessToken()
        if (!isOnlyAccessToken) {
            const refreshToken = await user.generateRefreshToken()
            user.refreshToken = refreshToken
            await user.save({validateBeforeSave: false})
            return {accessToken, refreshToken}
        }
        return {accessToken}
    } catch (error) {
        throw new ApiErrors(400, "generate access and refresh token failed")
    }
}

export default generateAccessAndRefreshToken