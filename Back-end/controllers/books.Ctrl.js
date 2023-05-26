
const bookShema = require('../models/books.model');
const fs = require('fs');
const path = require('path');
//import module sharp pour redimensionner les images
const sharp = require('sharp');

/*********** renvoie un tableau de tous les livres de la base de donnés *********/
exports.allBooks = (req, res ,next) => {                                
    bookShema.find()
      .then(books => res.status(200).json(books) )
      .catch(error => res.status(404).json({ error }));
};                                                             

/************* ajout d'un nouveau livre  a la basse de donnés  **************/
exports.addBook = async (req, res ,next) => {  

const bookObject = JSON.parse(req.body.book);
delete bookObject._id;
delete bookObject._userId;

const resizedImagePath = `images/resized_${req.file.filename}`;

sharp(req.file.path)
  .resize(537, 405)
  .toFile(resizedImagePath)
  .then(() => {
    fs.unlinkSync(req.file.path);

    const book = new bookShema({
      ...bookObject,
      userId: req.auth.userId,
      imageUrl: `${req.protocol}://${req.get('host')}/${resizedImagePath}`
    });

    book
      .save()
      .then(() => {
        res.status(201).json({ message: 'Objet enregistré !' });
      })
      .catch((error) => {
        fs.unlinkSync(resizedImagePath);
        res.status(400).json({ error });
      });
  })
  .catch((error) => {
    fs.unlinkSync(resizedImagePath);
    fs.unlinkSync(req.file.path);
    res.status(400).json({ error });
  });
};

/************* renvoie le livre sélectionné grace a sont id  **************/
exports.getOneBook = (req, res) => {                                            
    bookShema.findOne({ _id: req.params.id})
      .then(books => { res.status(200).json(books) })
      .catch(error => res.status(404).json({ error }));
};

/************* modification d'un livre  **************/
exports.modifyBook = (req, res, next) => { 

const bookId = req.params.id;
 
let resizedImagePath = null ;

if (req.file) {
  resizedImagePath = `images/resized_${req.file.filename}`;

  bookShema
  .findOne({ _id: bookId })
  .then((book) => {
    // si le livre n'est pas trouver
    if (!book) {
          return res.status(404).json({ message: 'Livre non trouvé' });
        }

    // si c'est bien l'auteur du livre
    if (book.userId !== req.auth.userId) {
          return res.status(401).json({ message: 'Non autorisé !' });
        }

    // récupération du non de la photo à supprimer dans la base de donnée
    const imageName = book.imageUrl.split('/images/resized_')[1];

    // suppression de l'image dans le dossier images du serveur 
                fs.unlink(`images/resized_${imageName}`, (error) => {
                  if (error) { console.error(`Erreur lors de la suppression de l'ancienne image :`, error); }
                  })

    // formatage de la nouvelle image   
    sharp(req.file.path)
      .resize(537, 405)
      .toFile(resizedImagePath)
      .then(() => {
        // suppression image d'origine dans le back end
        fs.unlinkSync(req.file.path)})
  
  .catch((error)=> res.status(404).json({error}))
})
} 

const bookObject = req.file
  ? {
      ...JSON.parse(req.body.book),
      imageUrl: `${req.protocol}://${req.get('host')}/${resizedImagePath}`
    }
  : { ...req.body };

    // Suppression du champ _userId pour des raisons de sécurité (éviter l'usurpation)
    delete bookObject._userId;

// mettre a jour la base de donnée
bookShema
    .updateOne({ _id: bookId },
              { ...bookObject,
                userId: req.auth.userId 
              })
    .then(() => res.status(200).json({ message : `l'objet à bien été mise à jour`}))
    .catch((error)=>{
        fs.unlinkSync(resizedImagePath);
        fs.unlinkSync(req.file.path);
        res.status(404).json({error});
    })
};

/************* suppression d'un livre  **************/
exports.deleteBook = (req, res, next) => {

  // recherche le livre par les parametre dans l'url (id)  
  bookShema.findOne({ _id: req.params.id}) 
    .then(book => {

        //compare userId de la base de donné a celle de la req
        if (book.userId != req.auth.userId) {
            res.status(401).json({message: 'Not authorized'});
        } else {

            //j'extrait le non de l'image dans la base de donnée et  je la supprime dans le back end 
            const filename = book.imageUrl.split('/images/resized_')[1];
            fs.unlink(`images/resized_${filename}`, () => {

                // je supprime le livre de la base de donnée
                bookShema.deleteOne({_id: req.params.id})
                    .then(() => { res.status(200).json({message: 'Objet supprimé !'})})
                    .catch(error => res.status(401).json({ error }));
            });
        }
    })
    .catch( error => {
        res.status(404).json({ error });
    });
};

/************* ajout du rating  **************/
exports.addRatingBook = (req, res ,next) => {

    const bookId = req.params.id;
    const  userId  = req.auth.userId;
    const  rating  = req.body.rating;

    // recherche le livre part l'id
    bookShema.findById(bookId)
        .then(book => {
        if (!book) {
            return res.status(404).json({ message: "Livre non trouvé" });
        }
            // on ajoute au tableau ratings dans le schema du livre conserné
            book.ratings.push({ userId, grade: rating });

            // Calcul du nouvel Rating
            const totalRatings = book.ratings.length;
            const sumRatings = book.ratings.reduce((sum, rating) => sum + rating.grade, 0);
            book.averageRating = sumRatings / totalRatings;

             book
                .save()
                .then(() => { res.status(201).json(book) })
                .catch(error => res.status(400).json({ error }));
        })
        .catch(error => { res.status(500).json({ error }) });
};

/************* renvoie un tableu des trois livres qui ont la meilleure note moyenne  **************/
exports.bestRating = (req, res, next) => {

    bookShema
        .find()
        .sort({ averageRating: -1 })
        .limit(3)
        .then(books => { res.status(200).json( books ) })
        .catch(error => { res.status(500).json({ error }) });  
};