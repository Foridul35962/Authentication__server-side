import dotenv from 'dotenv'
dotenv.config()
import app from './src/app.js'
import connectDB from './src/db/database.js'

const PORT = process.env.PORT || 3000

connectDB().then(()=>{
    app.listen(PORT,()=>{
        console.log(`server is running on http://localhost:${PORT}`);
    })
}).catch((err)=>{
    console.log('server connection failed',err);
})