import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import connectDB from "./utils/db.js";
import userRoute from "./routes/authRoutes.js";
dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
const corsOptions = {
  origin: "https://hr-dashboard-pink.vercel.app",
  credentials: true,
};
app.use(cors(corsOptions));


const PORT = process.env.PORT || 3000;

app.use("/api/v1/user", userRoute);
app.listen(PORT, () => {
  connectDB();
  console.log(`Server is running at port ${PORT}`);
});
