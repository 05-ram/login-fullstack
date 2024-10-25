import express, { response } from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import mysql from 'mysql';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';

const app = express();

const salt = 10;

app.use(express.json());
app.use(cors(
    {
        origin: ['http://localhost:3000'],
        methods: ['POST', 'GET'],
        credentials: true
    }
));
app.use(cookieParser());

const db = mysql.createConnection(
    {
        host: 'localhost',
        user: 'karthi',
        password: 'ram12345',
        database: 'login_db'
    }
)

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: 'You Are Not Authenticated' })
    }
    else {
        jwt.verify(token, 'jwt-secret-key', (err, decoded) => {
            if (err) {
                return res.json({ Error: 'Token is not Okay...' })
            }
            else {
                req.name = decoded.name;
                next();
            }
        })
    }
}

app.get('/', verifyUser, (req, res) => {
    return res.json({ Status: 'Success', name: req.name });
})

app.post('/register', (req, res) => {
    const sql = 'INSERT INTO login (`name`, `email`, `password`) VALUES (?, ?, ?)';
    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) return res.json({ Error: "Error in hashing password" });
        const values = [
            req.body.name,
            req.body.email,
            hash
        ]
        db.query(sql, values, (err, result) => {
            if (err) return res.json({ Error: err.message });
            return res.json({ Status: 'Success' })
        })
    })
})

app.post('/login', (req, res) => {
    const sql = 'Select * from login where email=?'
    db.query(sql, req.body.email, (err, data) => {
        if (err) return res.json({ Error: "Login error" })
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) return res.json({ Error: 'Password Comapre Error' })
                if (response) {
                    const name = data[0].name;
                    const token = jwt.sign({ name }, 'jwt-secret-key', { expiresIn: '1d' });
                    res.cookie('token', token);
                    return res.json({ Status: 'Success' })
                }
                else {
                    return res.json({ Error: 'Password Not Matched' })
                }
            })
        }
        else {
            return res.json({ Error: "No Mail Existed" })
        }
    })
})

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ Status: 'Success' })
})

app.listen(8082, () => {
    console.log('Running...')
})
