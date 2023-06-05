const webToken = require('jsonwebtoken');

/**** création d'une couche de securité ****/
require('dotenv').config();

module.exports = (req, res, next) => {
   try {
       const token = req.headers.authorization.split(' ')[1];
       const decodedToken = webToken.verify(token, process.env.SECRET);
       const userId = decodedToken.userId;
       req.auth = {
           userId: userId
       };
    next();
   } catch(error) {
       res.status(401).json({ error });
   }
};