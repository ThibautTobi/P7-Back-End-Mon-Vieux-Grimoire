const mongoose = require("mongoose");
const uniqueValidator = require('mongoose-unique-validator');

const userShema = mongoose.Schema({
    email : {type: String , required: true, unique:true },
    password : {type: String , required: true},
});

/****  j'ajoute le plugin pour étre sur que "unique" sera bien unique dans la base de donnés ****/
userShema.plugin(uniqueValidator);

module.exports = mongoose.model('user', userShema);