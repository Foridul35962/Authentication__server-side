class ApiErrors extends Error{
    constructor(statusCode, message='something wrong', error = []){
        super(message)
        this.statusCode = statusCode,
        this.error = error,
        this.success = false
    }
}

export default ApiErrors