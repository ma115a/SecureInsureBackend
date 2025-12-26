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
const PDFDocument = require('pdfkit')
const logger = require('./logger')


const saltRounds = 5
const app = express()
app.use(express.json())
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

function logToSiem(type, user, req, severity, details) {
    try {
        const ip = req.ip || req.socket.remoteAddress
        const url = req.originalUrl || req.url
        const method = req.method
        const timestamp = new Date().toISOString()

        const stmt = db.prepare('INSERT INTO siem (type, user, ip, url, method, severity, details, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        stmt.run(type, user, ip, url, method, severity, details, timestamp)
    } catch (error) {
        logger.error(`Failed to write to SIEM: ${error.message}`)
    }
}


async function send2FA(email, data) {
    const info = await transporer.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: '2-Factor Authentication for SecureInsure',
        text: data
    })
}

async function sendPolicyEmail(email, pdfBuffer, policyNumber) {
    try {
        await transporer.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: `Your SecureInsure Policy - ${policyNumber}`,
            text: 'Thank you for choosing SecureInsure. Please find your insurance policy attached to this email.',
            attachments: [
                {
                    filename: `Policy_${policyNumber}.pdf`,
                    content: pdfBuffer
                }
            ]
        })
        logger.info(`Policy email sent to ${email} for policy ${policyNumber}`)
    } catch (error) {
        logger.error(`Failed to send policy email to ${email}: ${error.message}`)
    }
}


function generate2FACode() {
    return Math.floor(100000 + Math.random() * 900000).toString()
}


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) return res.status(401).json({ success: false, message: "No token" })

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            logToSiem('AUTH_FAILURE', 'unknown', req, 'medium', `Invalid token: ${err.message}`)
            return res.status(403).json({ success: false, message: "Invalid token" })
        }
        const currentFingerprint = createFingerprint(req)
        if (decoded.fingerprint != currentFingerprint) {
            logToSiem('SESSION_HIJACK_ATTEMPT', decoded.userObject.username, req, 'high', 'Fingerprint mismatch')
            return res.status(403).json({ success: false, message: "Validity check failed" })
        }
        req.user = decoded
        next()
    })

}


function createPolicyPDF(row) {

    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: 50 })
        let buffers = []
        doc.on('data', buffers.push.bind(buffers))
        doc.on('end', () => resolve(Buffer.concat(buffers)))
        doc.on('error', reject)


        doc.fillColor('#3b82f6').fontSize(25).text('SecureInsure', { characterSpacing: 2 })
        doc.fillColor('#444').fontSize(10).text('Insurance Company', { characterSpacing: 1 })
        doc.moveDown(2)

        doc.rect(50, 120, 500, 40).fill('#f8fafc')
        doc.fillColor('#1e293b').fontSize(16).text(`Insurance policy: ${row.policy_number}`, 65, 133)
        doc.moveDown(4)
        doc.fillColor('#3b82f6').fontSize(12).text('Customer data ', 50)
        doc.underline(50, doc.y, 500, 1, { color: '#eee' })
        doc.moveDown(1)
        doc.fillColor('#444').fontSize(10)
        doc.text(`Name and Lastname: ${row.first_name} ${row.last_name}`)
        doc.text(`Username: ${row.username}`)
        doc.moveDown(2)

        doc.fillColor('#3bb82f6').fontSize(12).text('Coverage Details', 50)
        doc.moveDown(1)
        doc.fillColor('#444').fontSize(10)
        doc.text(`Product: ${row.policy_name}`)
        doc.text(`Type: ${row.type}`)
        doc.text(`Coverage amount: ${row.base_coverage.toLocaleString()} USD`)
        doc.moveDown(2)

        doc.rect(50, doc.y, 500, 50).fill('#eff6ff')
        doc.fillColor('#1e40af').text(`Valid from ${row.issue_date} to ${row.expiry_date}`)
        doc.end()
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
        logger.info(data)
        return data.access_token

    } catch (error) {
        logger.error(error)
        throw error

    }
}




app.get('/', (req, res) => {
    res.send('OK')
})


app.post('/api/register', async (req, res) => {
    try {
        const { name, lastname, username, password, email } = req.body

        if (!username || !password || !name || !lastname || !email) {
            logger.warn(`Registration attempt missing data`)
            return res.status(400).json({ success: false, message: "Data missing!" })
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds)
        const insertUser = db.prepare('INSERT INTO user (username, password, name, lastname, email) VALUES (?, ?, ?, ?, ?)')
        const insertUserResult = insertUser.run(username, hashedPassword, name, lastname, email)


        const { admin } = req.body

        const insertRole = db.prepare('INSERT INTO role (username, admin, regular) VALUES (?, ?, ?)')
        let insertRoleResult
        if (admin) {
            insertRoleResult = insertRole.run(username, 1, 1)
        } else {
            insertRoleResult = insertRole.run(username, 0, 1)
        }

        if (insertUserResult.changes == 1 && insertRoleResult.changes == 1) {
            logger.info(`User registered successfully: ${username}`)
            logToSiem('USER_REGISTRATION', username, req, 'info', 'New user registered')
            return res.json({ success: true, message: "User added sucessfully!" })
        }
    } catch (error) {
        logger.error(`Registration error: ${error.message}`)
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
            const getUserRole = db.prepare("SELECT * FROM role WHERE username = ?")
            const userRoleDb = getUserRole.get(username)
            let userRole
            if (userRoleDb) {
                if (userRoleDb.admin === 1) {
                    userRole = 'admin'
                } else userRole = 'regular'
            }


            const code2FA = generate2FACode()
            await send2FA(user.email, `Your 2-factor auth code is: ${code2FA}`)
            const codeExpiresAt = Date.now() + 5 * 60 * 1000

            pending2FA[username] = { code2FA, codeExpiresAt, user }
            logger.info(`Login successful, 2FA initiated for user: ${username}`)
            return res.json({ success: true, message: "Proceed to 2FA verification", code2FA })
        } else {
            logger.warn(`Login failed: Invalid password for user ${username}`)
            logToSiem('LOGIN_FAILURE', username, req, 'medium', 'Invalid password')
            return res.json({ success: false, message: "Invalid username or password" })
        }





    } catch (error) {
        logger.error(error)

    }
    res.send('OK')
})

app.post('/api/check-2fa', (req, res) => {
    const { username, code } = req.body

    if (!username || !code) {
        return res.status(400).json({ success: false, message: "Missing data" })
    }

    const record = pending2FA[username]

    if (!record) {
        logger.warn(`2FA check failed: No pending code for ${username}`)
        logToSiem('2FA_FAILURE', username, req, 'low', 'No pending code found')
        return res.status(400).json({ success: false, message: "Code not found" })
    }

    if (Date.now() > record.codeExpiresAt) {
        delete pending2FA[username]
        logger.warn(`2FA check failed: Code expired for ${username}`)
        logToSiem('2FA_FAILURE', username, req, 'low', 'Code expired')
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


        const token = jwt.sign({ userObject, fingerprint }, process.env.JWT_SECRET, { expiresIn: '1h' })
        logger.info(`2FA successful, token generated for user: ${username}`)
        logToSiem('LOGIN_SUCCESS', username, req, 'info', '2FA successful, token generated')
        return res.json({ success: true, message: "code good", token: token })
    } else {
        logger.warn(`2FA check failed: Invalid code for ${username}`)
        logToSiem('2FA_FAILURE', username, req, 'medium', 'Invalid code')
        return res.json({ success: false, message: "code bad" })
    }
})


app.get('/test', authenticateToken, (req, res) => {
    res.send('OK')
})


app.post('/api/add-policy', authenticateToken, async (req, res) => {
    const { name, description, basePrice, baseCoverage, type, validFor } = req.body

    if (!name || !description || !basePrice || !baseCoverage || !type || !validFor) {
        return res.status(400).json({ success: false, message: "Data missing" })
    }


    try {

        const addPolicy = db.prepare('INSERT INTO policy (name, description, base_price, base_coverage, type, valid_for) VALUES (?,?, ?, ?, ?, ?)')
        const addedPolicy = addPolicy.run(name, description, basePrice, baseCoverage, type, validFor)
        if (addedPolicy.changes === 1) {
            logger.info(`Policy added: ${name} by user ${req.user.userObject.username}`)
            logToSiem('POLICY_CREATION', req.user.userObject.username, req, 'info', `Policy ${name} created`)
            return res.json({ success: true, message: "Policy added sucessfully" })
        }

    } catch (error) {
        logger.error(`Error adding policy: ${error.message}`)
        return res.status(500).json({ success: false, message: "Internal server error" })

    }
})


app.get('/api/policies', authenticateToken, async (req, res) => {

    try {
        const getPolicies = db.prepare('SELECT * FROM policy')
        const policies = getPolicies.all()
        logger.info(`All policies fetched by ${req.user.userObject.username}`)

        return res.json({ sucess: true, message: "Policies fetched", policies })

    } catch (error) {
        logger.error(error)
        return res.status(500).json({ success: false, message: "Internal server error" })
    }
})


app.get('/api/user/policies', async (req, res) => {
    try {


        const getPolicies = db.prepare('SELECT * FROM purchased_policy pu INNER JOIN policy p on pu.policy_id = p.id WHERE username = ?')
        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(' ')[1]
        const user = jwt.verify(token, process.env.JWT_SECRET)
        const policies = getPolicies.all(user.userObject.username)
        logger.info(`User policies fetched for ${user.userObject.username}`)

        return res.json({ sucess: true, message: "User policies fetched", policies })

    } catch (error) {
        logger.error(error)
        return res.status(500).json({ success: false, message: "Internal server error" })
    }
})



app.post('/api/create-order', async (req, res) => {

    const { policyId, amount } = req.body

    try {

        const getPolicy = db.prepare("SELECT base_price, valid_for from policy WHERE id = ?")
        const policy = getPolicy.get(policyId)

        if (policy.base_price != amount) {
            logger.warn(`Price tampering detected for policy ${policyId}. Expected: ${policy.base_price}, Received: ${amount}`)
            logToSiem('DATA_TAMPERING', 'unknown', req, 'critical', `Price mismatch: Expected ${policy.base_price}, got ${amount}`)
            return res.json(400).json({ success: false, message: "Price has been tampered with" })
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
                    description: `${policy.name}`

                }],
                application_context: {
                    shipping_preference: 'NO_SHIPPING',
                    user_action: 'PAY_NOW'
                }
            })
        })

        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(' ')[1]
        const user = jwt.verify(token, process.env.JWT_SECRET)
        const policyNumber = `SG-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;

        const order = await response.json()
        // return res.status(response.status).json(order)
        const currentDate = new Date(Date.now())
        let expiry_date = new Date(currentDate.getTime())
        expiry_date.setDate(expiry_date.getDate() + Number(policy.valid_for))

        const addPolicy = db.prepare('INSERT INTO purchased_policy (purchase_id, policy_number, username, policy_id, status, issue_date, expiry_date) VALUES (?,?, ?, ?, ?, ?, ?)')

        const addedPolicy = addPolicy.run(order.id, policyNumber, user.userObject.username, policyId, 'UNPAID', currentDate.toLocaleDateString(), expiry_date.toLocaleDateString())

        if (addedPolicy.changes === 1) {
            logger.info(`Order created for policy ${policyId} by user ${user.userObject.username}. Order ID: ${order.id}`)
        }

        return res.status(response.status).json({ success: true, order })

    } catch (error) {
        logger.error(`Error creating order: ${error.message}`)
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

        if (!response.ok) {
            logger.error(`Capture failed for order ${req.body.orderId}: ${JSON.stringify(captureData)}`)
            return res.status(response.status).json({ success: false, captureData })
        }


        if (captureData.status === 'COMPLETED') {
            const authHeader = req.headers['authorization']

            const token = authHeader && authHeader.split(' ')[1]
            const user = jwt.verify(token, process.env.JWT_SECRET)
            const updatePurchasedPolicy = db.prepare(`UPDATE purchased_policy SET status = ? WHERE purchase_id = ?`)
            const updatedPurchasedPolicy = updatePurchasedPolicy.run('ACTIVE', captureData.id)

            logger.info(`Order captured successfully: ${captureData.id}. Policy status updated to ACTIVE.`)

            const getPolicy = db.prepare('SELECT policy_number from purchased_policy WHERE purchase_id = ?')
            const policy = getPolicy.get(captureData.id)

            const fullDetailsQuery = db.prepare('SELECT pp.*, p.name as policy_name, p.base_coverage, p.type, u.name as first_name, u.lastname as last_name, u.email FROM purchased_policy pp JOIN policy p on pp.policy_id = p.id JOIN user u on pp.username = u.username WHERE pp.purchase_id = ?')
            const details = fullDetailsQuery.get(captureData.id)

            if (details) {
                const pdfBuffer = await createPolicyPDF(details)
                await sendPolicyEmail(details.email, pdfBuffer, details.policy_number)
            }

            res.json({ success: true, message: 'Payment sucessfull', policy })
        } else {
            logger.warn(`Order capture status not COMPLETED: ${captureData.status}`)
            res.json({ success: false, message: "Payment failed" })
        }



    } catch (error) {
        logger.error(`Error capturing order: ${error.message}`)
        res.status(500)
    }
})


app.get('/api/users', async (req, res) => {
    try {

        const getUsers = db.prepare("SELECT u.username, u.name, u.lastname, r.admin, r.regular FROM user u INNER JOIN role r on u.username = r.username")

        const users = getUsers.all()
        logger.info(`User list fetched. Count: ${users.length}`)

        return res.json({ success: true, message: "Users fetched", users })

    } catch (error) {
        logger.error(`Error fetching users: ${error.message}`)
        res.status(500).json({ success: false, message: "Internal server error" })
    }
})



app.get('/api/policy/download/:policyNumber', authenticateToken, async (req, res) => {
    const { policyNumber } = req.params
    try {
        const query = db.prepare('SELECT pp.*, p.name as policy_name, p.base_coverage, p.type, u.name as first_name, u.lastname as last_name FROM purchased_policy pp JOIN policy p on pp.policy_id = p.id JOIN user u on pp.username = u.username WHERE pp.policy_number = ?')

        const policy = query.get(policyNumber)

        const pdfBuffer = await createPolicyPDF(policy)
        logger.info(`Policy PDF downloaded: ${policyNumber} by ${req.user.userObject.username}`)
        res.setHeader('Content-Type', 'application/pdf')
        res.setHeader('Content-Disposition', `attachment; filename=Policy_${policyNumber}.pdf`)
        res.send(pdfBuffer)

    } catch (error) {
        logger.error(`Error downloading policy PDF: ${error.message}`)
        res.status(500).json({ success: false, message: "Internal server error" })
    }
})


app.post('/api/siem/log', async (req, res) => {

    const { type, user, ip, url, method, severity, details, timestamp } = req.body
    if (!type || !user || !ip || !url || !method || !severity || !details || !timestamp) {
        return res.status(400).json({ success: false, message: "Data misssing" })
    }
    try {
        const addSiem = db.prepare('INSERT INTO siem (type, user, ip, url, method, severity, details, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        const siem = addSiem.run(type, user, ip, url, method, severity, details, timestamp)
        if (siem.changes == 1) {
            logger.info(`SIEM log entry added: ${type} - ${user}`)
            return res.json({ success: true, message: 'Log added' })
        }
        return res.status(500).json({ success: false, message: "Log adding failed" })
    } catch (error) {
        logger.error(`Error adding SIEM log: ${error.message}`)
        res.status(500).json({ success: false, message: "Internal server error" })
    }
})

app.get('/api/siem/logs', async (req, res) => {

    try {
        const getLogs = db.prepare('SELECT * FROM siem')
        const logs = getLogs.all()
        logger.info(`SIEM logs fetched. Count: ${logs.length}`)

        return res.json({ success: true, message: "Logs fetched", logs })

    } catch (error) {
        logger.error(`Error fetching SIEM logs: ${error.message}`)
        res.status(500).json({ success: false, message: "Internal server error" })
    }
})

const PORT = 8443
https.createServer(sslOptions, app).listen(PORT, async () => {
    try {

        db = new Database('./SecureInsure.db')
        logger.info(`Server running on port ${PORT}`)
        logger.info("database connected")
        paypalToken = await getPayPalAccessToken()
        logger.info(paypalToken)
    } catch (error) {
        logger.error(error)
    }
})
