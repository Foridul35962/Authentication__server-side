import express from 'express'
import * as authController from '../controllers/auth.controllers.js'
import verifyJwt from '../middlewares/auth.middlewares.js'

const auth = express.Router()

auth.post('/register',authController.registerUser)
auth.post('/loggedIn', authController.userLoggedIn)
auth.post('/loggedOut', verifyJwt, authController.userLoggedOut)
auth.post('/sendVerifyOtp', authController.sendVerifyOtp)
auth.post('/verifyEmail', authController.verifyEmail)
auth.post('/reset-password-otp', authController.sendPassResetOtp)
auth.post('/reset-password', authController.resetPass)

export default auth