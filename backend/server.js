const express = require("express")
const dotEnv = require("dotenv")
// const {MongoClient} = require("mongodb")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express()

dotEnv.config()

const port = process.env.PORT || 5000
app.use(express.json())


mongoose.connect(process.env.MONGO_URL)
    .then(() => {
        console.log("Mongodb Connected Successfully")
        app.listen(port, ()=>{
            console.log(`Server running at http://localhost:${port}`)
        })
    })
    .catch((error) => {
        console.log("Error connecting to MongoDB:", error)
    })


const userSchema =new mongoose.Schema({
    username : String,
    password : String,
    email : String,
    mobile : Number
})

const userModel = mongoose.model("users", userSchema)


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Access token not provided" });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: "Invalid or expired token" });
      }
      req.user = user;
      next();
    });
};

// CREATE API 
app.post("/getusers/", async (req, res) => {
    try {
      const { username, password, email, mobile} = req.body;
      const existingUser = await userModel.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new userModel({ username, password: hashedPassword, email, mobile });
      const savedUser = await newUser.save();
      console.log("User added successfully");
      res.status(201).json(savedUser);
    } catch (error) {
      console.error("Error adding user:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
});
  
// GET API READ ONLY
app.get("/getusers/", async (req, res) => {
    try {
      const userData = await userModel.find();
      res.json(userData);
    } catch (error) {
      console.error("Error getting users:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
});
  
  // // UPDATE API 
app.put("/getusers/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { username, password, email, mobile, location, gender } = req.body;
      const updatedUser = await userModel.findByIdAndUpdate(id, { username, password, email, mobile, location, gender }, { new: true });
      if (!updatedUser) {
        return res.status(404).json({ error: "User not found" });
      }
      console.log("User updated successfully");
      res.json(updatedUser);
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
});
  
  // // DELETE API 
app.delete("/getusers/:id", async (req, res) => {
    try {
        const deletedUser = await userModel.findByIdAndDelete(req.params.id);
        if (!deletedUser) {
        return res.status(404).json({ error: "User not found" });
        }
        console.log("User deleted successfully");
        res.json("User deleted successfully");
    } catch (error) {
        console.error("Error deleting user:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


// REGISTER API
app.post('/registers/', async (req, res) => {
  try {
    const { username, password, email, mobile } = req.body;
    const existingUser = await userModel.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new userModel({ username, password: hashedPassword, email, mobile});
    await newUser.save();
    res.send('User created successfully');
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).send(error.message);
  }
});
  
// Login
app.post("/login/", async (req, res) => {
    try {
      const { username, password } = req.body;
      const user = await userModel.findOne({ username });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const isPasswordMatched = await bcrypt.compare(password, user.password);
      if (isPasswordMatched) {
        const payload = { username: user.username };
        const jwtToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' }); // Token expires in 30 days
        res.json({ token: jwtToken });
      } else {
        return res.status(401).json({ error: "Invalid password" });
      }
    } catch (error) {
      console.error("Error logging in:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
});
  
