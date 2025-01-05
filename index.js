import express from "express"
import bodyParser from "body-parser"
import {open} from "sqlite"
import { config } from "dotenv"
import crypto from "crypto"
import sqlite3 from "sqlite3";
import cookieParser from "cookie-parser"
import jwt from 'jsonwebtoken'

const app=express()
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended:true}))
app.use(cookieParser())
config()
const port=process.env.PORT
let db
const secret=process.env.DB_SECRET

app.listen(port,async()=>{
    try{
        db=await open({
            filename: './users.db',
            driver: sqlite3.Database,
        })
        await db.run(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL
        )
        `)
        console.log(`Server started at port ${port}`)
    }catch(e){
        console.log(e.message)
    }
})

async function ValidPassword(password){
    if(password.length<8){
        throw new Error('Password must be 8 characters long')
    }
}
async function CheckUser(username,err){
    const query='SELECT 1 FROM users WHERE username=? LIMIT 1'
    const row=await db.get(query,[username])
    if(row){
        if(err){
            throw new Error('User already exists')
        }
        console.log('User exists')
    }
}
async function AssignToken(username,hashed,name,res){
    const token=await jwt.sign({username,hashed,name},secret,{expiresIn:'3d'})
    await res.cookie('auth_token',token,{
        maxAge:3600000*24*3
    })
}
async function Authenticate(req,res,next){
    try{
        const token=await req.cookies.auth_token
        if(!token){
            return res.status(300).send('No token')
        }
        await jwt.verify(token,secret,(err,dec)=>{
            if(err){
                return res.status(403).send('Invalid Token')
            }
            req.userdata={username:dec.username,name:dec.name}
            next()
        })
    }catch(e){
        console.log(e.message)
        res.status(500).send('Internal Server error')
    }
}

app.post('/signup',async(req,res)=>{
    try{
        const {username,password,name}=req.body
        await CheckUser(username,true)
        await ValidPassword(password)
        const hash= crypto.createHash('sha256')
        hash.update(password)
        const hashed=hash.digest('hex')
        console.log('Hashed password:',hashed)
        await db.run('INSERT INTO users (username,password,name) VALUES (?,?,?)',[username,hashed,name])
        console.log(`${username} added as a user`)
        await AssignToken(username,hashed,name,res)
        await res.send(`${username} added as a user`)
    }catch(e){
        console.log(e.message)
        res.send(e.message)
    }
})

app.post('/login',async(req,res)=>{
    try{
        const {username,password}=await req.body
        await CheckUser(username,false)
        const hashed=await crypto.createHash('sha256').update(password).digest('hex')
        const verify=await db.get('SELECT username,password,name FROM users WHERE username=?',[username])
        if(verify && verify.password==hashed){
            console.log('User authenticated')
        }else{
            throw new Error('Incorrect username or password')
        }
        await AssignToken(username,hashed,verify.name,res)
        await res.send(`Welcome ${username}`)

    }catch(e){
        console.log(e.message)
        res.send(e.message)
    }
})

app.get('/home',Authenticate,(req,res)=>{
    console.log(req.userdata)
    res.json(req.userdata)
})
app.get('/drop_users', async (req,res)=>{
    try{
        await db.run('DROP TABLE IF EXISTS users')
        res.send('Dropped table')
    }catch(e){
        console.log(e)
    }
})
app.get('/users',async(req,res)=>{
    try{
        const data=await db.all('SELECT * FROM users',[])
        console.log(data)
        res.send(data)
    }catch(er){
        console.log(er)
        res.send(er.message)
    }
})


