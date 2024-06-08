const db = require("../models");
const config = require("../config/auth.connfig");
const User = db.user;
const Role = db.role;

const Op = db.Sequelize.Op;
var jwt = require("jsonwebtoken");
var bcrypt = require('bcryptjs');

exports.signup = (req, res) => {
    //Save User to Database
    User.create({
        username: req.query.username,
        email: req.query.email,
        password: bcrypt.hashSync(req.query.password, 8)
    })
    .then(user => {
        if(req.query.roles){
            Role.findAll({
                where: {
                    name:{
                        [Op.or]: req.query.roles
                    }
                }
            })
            .then(roles => {
                user.setRoles(roles).then(()=> {
                    res.send({message: "User was registered successfully!"});
                    
                })
            })
        }else{
            //user role = 1
            user.setRoles([1]).then(()=> {
                res.send({message: "User was registered successfully!"})
            })
        }
    })
    .catch(err => {
        res.status(500).send({message: err.message})
    })
}

exports.signin = (req, res) => {
    User.findOne({
        where: {
            username: req.query.username
        }
    })
    .then(user => {
        if(!user) {
            res.status(404).send({
                message: "User not found!"
            })
        }
        
        const passwordIsValid = bcrypt.compareSync(
            req.query.password,
            user.password
        )

        if(!passwordIsValid){
            res.status(401).send({
                accessToken: null,
                message: "Invalid Password!"
            })
        }

        const token = jwt.sign(
            {id: user.id},
            config.secret,
            {
                algorithm: 'HS256',
                allowInsecureKeySizes: true,
                expiresIn: 86400
            }
        )

        var authorities = [];
        user.getRoles().then(roles => {
            for(let i=0; i<roles.length; i++){
                authorities.push("ROLE_" + roles[i].name.toUpperCase());

            }
            res.status(200).send({
                id: user.id,
                username: user.username,
                email: user.email,
                roles: authorities,
                accessToken: token
            })
        })

    })

    .catch(err => {
        res.status(500).send({message: err.message})
    })
}