class ApiError extends Error{

    constructor(status, message){
        this.status = status
        this.message = message
    }

    static badRequest(message){
        return new ApiError(400, message)
    }

    static forbidden(message){
        return new ApiError(403, message)
    }
    static unatorized(message){
        return new ApiError(401, message)
    }
    static internal(message){
        return new ApiError(500, message)
    }

}

module.exports = ApiError