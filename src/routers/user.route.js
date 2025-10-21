import express from 'express'
import * as userController from '../controllers/user.controller.js'
import verifyJwt from '../middlewares/auth.middlewares.js'

const user = express.Router()

user.get('/', verifyJwt, userController.getUser)

export default user