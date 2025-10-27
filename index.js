import dotenv from 'dotenv'
dotenv.config()
import app from './src/app.js'
import connectDB from './src/db/database.js'

const PORT = process.env.PORT || 3000

// connectDB().then(()=>{
//     app.listen(PORT,()=>{
//         console.log(`server is running on http://localhost:${PORT}`);
//     })
// }).catch((err)=>{
//     console.log('server connection failed',err);
// })

let isConnected = false;

export default async function handler(req, res) {
    if (!isConnected) {
        try {
            await connectDB()
            isConnected = true
            console.log('DB Connected')
        } catch (err) {
            console.error('DB Connection Failed', err)
            return res.status(500).json({ error: 'DB connection failed' })
        }
    }

    return app(req, res)
}