const errorHandler = (err, req, res, next)=>{
    const statusCode = err.statusCode || 500
    return res
        .status(statusCode)
        .json({
            success: err.success || false,
            message : err.message || "Internal server Error",
            error: err.error || [],
            data: err.data || null
        })
}

export default errorHandler