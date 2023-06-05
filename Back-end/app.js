const express = require ('express');
const mongoose = require('mongoose');
const path = require('path');

/** securisation : configuration des en-têtes HTTP, la protection contre les attaques XSS, la désactivation de la mise en cache côté client, etc. **/
const helmet = require('helmet');

/** plugin  contre les attaques d'injection de code malveillant dans les requêtes MongoDB **/
const mongoSanitize = require('mongo-sanitize');

/**** création d'une couche de securité ****/
require('dotenv').config();

/** securisation limite brut force **/
const rateLimit = require('express-rate-limit');

/**** import de mes différentes routes ****/
const books_Routes = require('./routes/books.route');
const user_Routes = require('./routes/user.route');

const app = express();

// Configure le rate limiter
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // Fenêtre de temps (5 minutes en millisecondes)
  max: 200, // Nombre maximal de requêtes autorisées dans la fenêtre de temps
  message: 'Trop de requêtes. Veuillez réessayer plus tard.', // Message d'erreur à envoyer en cas de dépassement du taux limite
});

app.use(limiter);

/*********** connection mongo db ***********/
mongoose.connect(process.env.DB_URL,
  { useNewUrlParser: true,
    useUnifiedTopology: true })
  .then(() => console.log('Connexion à MongoDB réussie !'))
  .catch(() => console.log('Connexion à MongoDB échouée !'));


// Utilisez le middleware Helmet avec la politique de ressource cross-origin appropriée
app.use(helmet.crossOriginResourcePolicy({ policy: 'cross-origin' }));

/** intercepte tout en format json ce qui nous donne le json dans req.body **/
app.use(express.json());

/******* ajout dans le header ******/
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content, Accept, Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  next();
});

/** utilisation du plugin mongo sanitize**/
app.use((req, res, next) => {
  // Nettoie les valeurs des paramètres de requête
  req.body = mongoSanitize(req.body);
  req.query = mongoSanitize(req.query);
  next();
});

/**** dispatch routage *****/
app.use(books_Routes);
app.use(user_Routes);
// gestion statique des fichier images dans le sous dossier images
app.use('/images', express.static(path.join(__dirname, 'images')));


module.exports = app;