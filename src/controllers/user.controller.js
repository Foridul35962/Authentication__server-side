import ApiErrors from "../utils/ApiError.js";
import ApiResponse from "../utils/ApiResponse.js";
import asyncHandler from "../utils/asyncHandler.js";

export const getUser = asyncHandler(async (req, res) => {
    const user = req.user
    if (!user) {
        throw new ApiErrors(404, 'user not found')
    }
    return res
        .status(200)
        .json(
            new ApiResponse(200, user, 'user fetched successfully')
        )
})