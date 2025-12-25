require('dotenv').config()
const https = require('https')
const fs = require('fs')
const express = require('express')
const path = require('path')
const Database = require('better-sqlite3')
const bcrypt = require('bcrypt')
const nodemailer = require('nodemailer')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')


const saltRounds = 5
const app = express()
app.use(express.json(0))
let db
let paypalToken


let pending2FA = {}


const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, '../key.pem')),
    cert: fs.readFileSync(path.join(__dirname, '../cert.pem'))
}


const transporer = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
})

function createFingerprint(req) {
    const userAgent = req.headers['user-agent'] || 'unknown'
    const ip = req.ip || req.socket.remoteAddress
    return crypto.createHash('sha256').update(userAgent + ip).digest('hex')
}


async function send2FA(email, data) {
    const info = await transporer.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: '2-Factor Authentication for SecureInsure',
        text: data
    })
}


function generate2FACode() {
    return Math.floor(100000 + Math.random() * 900000).toString()
}


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) return res.status(401).json({ success: false, message: "No token" })

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ success: false, message: "Invalid token" })
        const currentFingerprint = createFingerprint(req)
        if (decoded.fingerprint != currentFingerprint) {
            return res.status(403).json({ success: false, message: "Validity check failed" })
        }
        req.user = decoded
        next()
    })

}


async function getPayPalAccessToken() {

    try {
        const auth = Buffer.from(`${process.env.PAYPAL_CLIENT}:${process.env.PAYPAL_SECRET}`).toString('base64')
        const response = await fetch(`${process.env.PAYPAL_URL}/v1/oauth2/token`, {
            method: "POST",
            body: "grant_type=client_credentials",
            headers: {
                Authorization: `Basic ${auth}`,
                "Content-Type": "application/x-www-form-urlencoded"
            }
        })

        if (!response.ok) throw new Error('Paypal authentication failed')


        const data = await response.json()
        console.log(data)
        return data.access_token

    } catch (error) {
        console.log(error)
        throw error

    }
}




app.get('/', (req, res) => {
    console.log(req)
    res.send('OK')
})


app.post('/api/register', async (req, res) => {
    console.log('register called')
    try {
        const { name, lastname, username, password, email } = req.body

        if (!username || !password || !name || !lastname || !email) {
            return res.status(400).json({ success: false, message: "Data missing!" })
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds)
        const insertUser = db.prepare('INSERT INTO user (username, password, name, lastname, email) VALUES (?, ?, ?, ?, ?)')
        const insertUserResult = insertUser.run(username, hashedPassword, name, lastname, email)
        console.log(insertUserResult)


        const { admin } = req.body

        const insertRole = db.prepare('INSERT INTO role (username, admin, regular) VALUES (?, ?, ?)')
        let insertRoleResult
        if (admin) {
            insertRoleResult = insertRole.run(username, 1, 1)
            console.log(insertRoleResult)
        } else {
            insertRoleResult = insertRole.run(username, 0, 1)
            console.log(insertRoleResult)
        }

        if (insertUserResult.changes == 1 && insertRoleResult.changes == 1) {
            return res.json({ success: true, message: "User added sucessfully!" })
        }
    } catch (error) {
        console.log(error.message)
        return res.status(500).json({ success: false, message: "Internal server error" })
    }
})


app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body

        if (!username || !password) {
            return res.status(400).json({ success: false, message: "Data missing!" })
        }

        const getUser = db.prepare("SELECT * FROM user WHERE username = ?")
        const user = getUser.get(username)


        const passwordsMatch = await bcrypt.compare(password, user.password)

        if (passwordsMatch) {
            console.log(passwordsMatch)
            console.log(user)

            const getUserRole = db.prepare("SELECT * FROM role WHERE username = ?")
            const userRoleDb = getUserRole.get(username)
            let userRole
            if (userRoleDb) {
                if (userRoleDb.admin === 1) {
                    userRole = 'admin'
                } else userRole = 'regular'
            }


            // await send2FA(user.email, '123456')
            const code2FA = generate2FACode()
            const codeExpiresAt = Date.now() + 5 * 60 * 1000
            console.log(code2FA)

            pending2FA[username] = { code2FA, codeExpiresAt, user }
            console.log(pending2FA)
            return res.json({ success: true, message: "Proceed to 2FA verification", code2FA })
        } else {
            return res.json({ success: false, message: "Invalid username or password" })
        }





    } catch (error) {
        console.log(error)

    }
    res.send('OK')
})

app.post('/api/check-2fa', (req, res) => {
    const { username, code } = req.body
    console.log(req.body)

    if (!username || !code) {
        return res.status(400).json({ success: false, message: "Missing data" })
    }

    const record = pending2FA[username]

    if (!record) {
        return res.status(400).json({ success: false, message: "Code not found" })
    }

    if (Date.now() > record.codeExpiresAt) {
        delete pending2FA[username]
        return res.status(401).json({ success: false, message: "Code has expired" })
    }

    if (record.code2FA === code) {

        const getUser = db.prepare("SELECT u.username, u.name, u.lastname, r.admin, r.regular FROM user u INNER JOIN role r on u.username = r.username WHERE u.username = ?")
        const user = getUser.get(username)

        const role = user.admin === 1 ? 'admin' : 'regular'
        const userObject = {
            username: user.username,
            name: user.name,
            lastname: user.lastname,
            role: role
        }
        delete pending2FA[username]
        const fingerprint = createFingerprint(req)


        const token = jwt.sign({ userObject }, process.env.JWT_SECRET, { expiresIn: '1h' })
        return res.json({ success: true, message: "code good", token: token })
    } else {
        return res.json({ success: false, message: "code bad" })

    }
})


app.get('/test', authenticateToken, (req, res) => {
    res.send('OK')
})


app.post('/api/add-policy', async (req, res) => {
    const { name, description, basePrice, baseCoverage, type } = req.body
    console.log(req.body)

    if (!name || !description || !basePrice || !baseCoverage || type) {
        return res.status(400).json({ success: false, message: "Data missing" })
    }


    try {

        const addPolicy = db.prepare('INSERT INTO policy (name, description, base_price, base_coverage, type) VALUES (?, ?, ?, ?, ?)')
        const addedPolicy = addPolicy.run(name, description, basePrice, baseCoverage, type)
        if (addedPolicy.changes === 1) {
            return res.json({ success: true, message: "Policy added sucessfully" })
        }

    } catch (error) {
        console.log(error)
        return res.status(500).json({ success: false, message: "Internal server error" })

    }
})


app.get('/api/policies', async (req, res) => {

    try {
        const getPolicies = db.prepare('SELECT * FROM policy')
        const policies = getPolicies.all()
        // console.log(policies)

        return res.json({ sucess: true, message: "Policies fetched", policies })

    } catch (error) {
        console.log(error)
        return res.status(500).json({ success: false, message: "Internal server error" })
    }
})



app.post('/api/create-order', async (req, res) => {

    const { policyId, amount } = req.body

    try {

        const getPolicy = db.prepare("SELECT base_price from policy WHERE id = ?")
        const policy = getPolicy.get(policyId)
        if (policy.base_price === amount) {
            console.log('good boy')
        }



        const response = await fetch(`${process.env.PAYPAL_URL}/v2/checkout/orders`, {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${paypalToken}`
            },
            body: JSON.stringify({
                intent: 'CAPTURE',
                purchase_units: [{
                    amount: { currency_code: 'USD', value: amount.toFixed(2) },
                    description: 'Order #1001'

                }],
                application_context: {
                    shipping_preference: 'NO_SHIPPING', // Ključno za digitalne usluge/osiguranje
                    user_action: 'PAY_NOW'
                }
            })
        })

        const order = await response.json()
        res.status(response.status).json(order)

    } catch (error) {
        console.log(error)
        res.status(500).json({ success: false, message: "Internal server error" })

    }
})


app.post('/api/capture-order', async (req, res) => {
    try {
        const response = await fetch(`${process.env.PAYPAL_URL}/v2/checkout/orders/${req.body.orderId}/capture`, {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${paypalToken}`
            }
        })


        const captureData = await response.json()
        console.log(captureData)
        res.json({ success: true, message: 'uga buga' })



    } catch (error) {
        console.log(error)

        res.status(500)
    }
})


app.get('/api/users', async (req, res) => {
    try {

        const getUsers = db.prepare("SELECT u.username, u.name, u.lastname, r.admin, r.regular FROM user u INNER JOIN role r on u.username = r.username")

        const users = getUsers.all()
        console.log(users)

        return res.json({ success: true, message: "Users fetched", users })

    } catch (error) {
        console.log(error)
        res.status(500).json({ success: false, message: "Internal server error" })
    }
})


const PORT = 8443
https.createServer(sslOptions, app).listen(PORT, async () => {
    try {

        db = new Database('./SecureInsure.db')
        console.log(`Server running on port ${PORT}`)
        console.log("database connected")
        paypalToken = await getPayPalAccessToken()
        console.log(paypalToken)
    } catch (error) {
        console.log(error)
    }
})
