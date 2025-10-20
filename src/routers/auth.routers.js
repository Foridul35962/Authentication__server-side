import express from 'express'
import * as authController from '../controllers/auth.controllers.js'
import verifyJwt from '../middlewares/auth.middlewares.js'

const auth = express.Router()

auth.post('/register',authController.registerUser)
auth.post('/loggedIn', authController.userLoggedIn)
auth.post('/loggedOut', verifyJwt, authController.userLoggedOut)

export default auth