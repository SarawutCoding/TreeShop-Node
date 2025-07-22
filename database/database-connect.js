const mysql = require('mysql2');

const cone = mysql.createPool({
    host:'localhost',
    user:'root',
    password:'111960Za_Yao',
    database:'My_TreeShop'
}).promise();

module.exports = cone;
