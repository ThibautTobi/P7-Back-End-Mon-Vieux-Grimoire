const userShema = require('../models/user.model');

/**********  module hash mot de passe **********/
const bcrypt = require('bcrypt');

/**********  création token **********/
const webToken = require('jsonwebtoken');

/**********  module verification email valide **********/
const emailValidator = require('email-validator');

/***************************************** authentification utilisateur *************************************/

/************* identification et verification utilisateur , renvoi id utilisateur et un token web json  contenant id utilisateur **************/
exports.signup = (req, res ,next) => {     
    const email = req.body.email;
    // Vérification de l'email valide
    if (!emailValidator.validate(email)) {
        return res.status(400).json({ message: "Email invalide" });
    }
    bcrypt.hash(req.body.password, 10)
        .then(hash => {
            const user = new userShema({
                email: req.body.email,
                password: hash
            });
            user.save()
            .then(() => res.status(201).json({ message : 'utilisateur créé !'}))
            .catch(error => res.status(400).json({ error }));
        })
        .catch(error => res.status(500).json({ error }));
};

/************* ajout utilisateur a la base de donnés et hachage du mot de pass(crypto)  **************/
exports.login = (req, res ,next) => {
    // recherche de l'utilisateur par sont email grace a findOne
    userShema.findOne({email: req.body.email})
        .then(user => {
            if(user === null){
                // si l'email n'est pas trouvé
                res.status(401).json({ message : 'identifiant ou mot de passe incorrecte'});
            } 
            else {
                //comparaison entre le mot de passe fournie et celui de la base de donnés
                bcrypt.compare(req.body.password, user.password)
                .then(valid => {
                    if(!valid) {
                        res.status(401).json({ message : 'identifiant ou mot de passe incorrecte'})
                    } 
                    else {
                        res.status(200).json({
                            userId: user._id,
                            // création du token avec jsonwebtoken expiration au bout de 24h
                            token: webToken.sign(
                                { userId: user._id },
                                'TOKEN_SECRET_OPENCLASSROOM',
                                { expiresIn: '24h' }
                            )
                        });
                    }
                })
                .catch(error => { res.status(500).json({ error })});
            }
        })
        .catch(error => {res.status(500).json({ error })})
};