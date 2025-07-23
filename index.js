const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const cone = require('./database/database-connect.js');
const {body, validationResult} = require('express-validator');


const app = express();
app.use(express.urlencoded({extended:false}));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 3600 * 1000
}));

const ifNotLoggedIn = (req, res, next) => {
    if (!req.session.isLoggedIn) {
        return res.render('log-reg/login-register');
    }
    next();
}

const ifLoggedIn = (req, res, next) => {
    if (req.session.isLoggedIn) {
        return res.redirect('/');
    }
    next();
}

app.get('/', ifNotLoggedIn, (req, res, next)=>{
    cone.execute("select name from users where id = ?", [req.session.userID])
    .then(([rows]) => {
        res.render('home', {name: rows[0].name})
    })
})

app.post('/register', ifLoggedIn, [
    body('user_email', 'Invalid Email Address').isEmail().custom((value)=>{
        return cone.execute('select email from users where email = ?', [value])
        .then(([rows])=>{
            if (rows.length > 0) {
                return Promise.reject('This email already in user!')
            }
            return true;
        })
    }),
    body('user_name', 'Username is empty').trim().not().isEmpty(),
    body('user_password', 'The password must be of minimun length 6 charaters').trim().isLength({min:6})
], 
(req, res, next)=>{
    const validation_result = validationResult(req);
    const {user_name, user_password, user_email} = req.body;
    if (validation_result.isEmpty()) {
        bcrypt.hash(user_password, 12).then((hash_pass)=>{
            cone.execute('insert into users (name, email, password) values(?, ?, ?)', [user_name, user_email, hash_pass])
            .then(result => {
                res.send(`Your account has creted successfully, Now you can <a href="/">Login</a>`);
            }).catch(err => {
                if (err) throw err;
            })
        }).catch(err => {
                if (err) throw err;
        })
    } else {
        let allError = validation_result.array().map((error) => { // 💡 แก้ไขตรงนี้: ใช้ .array()
            return error.msg;
        });

        res.render('log-reg/login-register', {
            register_error: allError,
            old_data: req.body
        })
    }
});

app.post('/', ifLoggedIn , [
    body('user_email').custom((value)=>{
        return cone.execute('select email from users where email = ?', [value])
        .then(([rows]) => {
            if (rows.length == 1) {
                return true;
            }
            return Promise.reject('Invalid Email Address')
        });

    }),
    body('user_password', 'Password is empty').trim().not().isEmpty()
], (req, res)=>{
    const validation_result = validationResult(req);
    const {user_password, user_email} = req.body;
    if (validation_result.isEmpty()) {
        cone.execute('select * from users where email = ?', [user_email])
        .then(([rows]) => {
            bcrypt.compare(user_password, rows[0].password).then(compare_result => {
                if (compare_result === true) {
                    req.session.isLoggedIn = true;
                    req.session.userID = rows[0].id;
                    res.redirect('/');
                } else{
                    res.render('log-reg/login-register', {
                        login_errors: ['Invalid Password']
                    })
                }
            }).catch(err => {
                if (err) throw err;
            })
        }).catch(err => {
                if (err) throw err;
        })
    } else {
        let allError = validation_result.array().map((error) => { // 💡 แก้ไขตรงนี้: ใช้ .array()
            return error.msg;
        });

        res.render('log-reg/login-register', {
            login_errors: allError
        })
    }
});

app.get('/logout', (req, res) => {
    req.session = null;
    res.redirect('/');
});

const port = 3000;

app.listen(port,()=>{
    console.log(`Sever Start localhost ${port}`);
});