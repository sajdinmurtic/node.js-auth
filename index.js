require('dotenv').config()
require('./config/db').connect()
const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const User = require('./model/user')
const auth = require('./middleware/auth')
const app = express()

app.use(express.json())

const http = require('http')
const server = http.createServer(app)
app.post('/register', async(req, res)=> {
    try {
        const { name, email, password} = req.body
        if(!(email && password && name )) {
            res.status(400).send('All input is required')
        }
        const oldUser = await User.findOne( { email})

        if(oldUser) {
            return res.status(409).send('User already exist')
        }

        hashedPassword = await bcrypt.hash(password, 10)

        const user = await User.create({
            name:req.body.name,
            email: req.body.email,
            password: hashedPassword,
        })

        const token = jwt.sign(
            { user_id: user._id, email},
            process.env.TOKEN_KEY,
            {
                expiresIn: '2h',
            }
        )

        user.token = token

        res.status(201).json(user)
    }catch(err) {
        console.log(err)
    }
})
app.post('/login', async (req, res)=> {
    try {
        const { email, password} = req.body
        if(!(email && password)) {
            res.status(400).send('All input is required')
        }

        const user = await User.findOne({ email})

        if(user && (await bcrypt.compare(password, user.password))) {
            const token = jwt.sign(
                { user_id: user._id, email},
                process.env.TOKEN_KEY,
                {
                 expiresIn: '2h',   
                }
            )

            user.token = token

            res.status(200).json(user)
        }
        res.status(400).send('Invalid credentials')
    }catch (err) {
        console.log(err)
    }
})



app.use('*', (req, res)=> {
    res.status(404).json({
        success: 'false',
        error: {
            statusCode: 404,
            message:'You reached an undefined route'

        }
    })
})

const port = process.env.PORT || 8080

server.listen(port, ()=> {
    console.log(`Server running on port ${port}`)
})