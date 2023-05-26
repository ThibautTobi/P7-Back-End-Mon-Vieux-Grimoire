const express = require ('express');
const booksCtrl = require('../controllers/books.Ctrl');

// ajoute une demande d'authentification avec auth
const auth = require('../middleware/auth');
// gére les fichier images 
const multer = require('../middleware/multer-config');

const router = express.Router();

router.get('/api/books', booksCtrl.allBooks);
router.get('/api/books/bestrating', booksCtrl.bestRating);
router.post('/api/books', auth, multer, booksCtrl.addBook);
router.get('/api/books/:id', booksCtrl.getOneBook);
router.put('/api/books/:id', auth, multer, booksCtrl.modifyBook);
router.delete('/api/books/:id', auth, booksCtrl.deleteBook);
router.post('/api/books/:id/rating', auth, booksCtrl.addRatingBook);

module.exports = router;