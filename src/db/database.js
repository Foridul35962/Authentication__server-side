import mongoose from "mongoose";
import { DB_NAME } from "../utils/constance.js";

const connectDB = async()=>{
    await mongoose.connect(`${process.env.MONGODB_URL}/${DB_NAME}`).then((connectionIstance)=>{
        console.log('Database is connected');
        return connectionIstance
    }).catch((err)=>{
        console.log('Database connection failed', err.message);
        throw err
    })
}

export default connectDB