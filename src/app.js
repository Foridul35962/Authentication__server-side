import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'

const app = express()

//local file import
import errorHandler from './utils/errorHandler.js'

//setting request URL
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

//setting for req.body
app.use(express.urlencoded({extended: false}))
app.use(express.json())

//setting for cookies
app.use(cookieParser())

//routers

//global error handler
app.use(errorHandler)

export default app