class ApiErrors extends Error{
    constructor(statusCode, message='something wrong', error = []){
        this.statusCode = statusCode,
        this.message = message,
        this.error = error,
        this.success = false
    }
}

export default ApiErrors