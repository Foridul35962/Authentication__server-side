import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'

const app = express()


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

export default app