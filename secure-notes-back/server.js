require('dotenv').config();

const sanitizeHtml = require('sanitize-html');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const db = require('./database');
const authMiddleware = require('./middleware/auth');
const isAdmin = require('./middleware/isAdmin');

app.use(helmet());
app.use(cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
}));
app.use(express.json());

const saltRounds = 10;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,

    standardHeaders: true,
    legacyHeaders: false,

    handler: (req, res) => {
        res.status(429).json({
            error: "Trop de tentatives de connexion. Veuillez patienter 15 minutes avant de réessayer."
        });
    }
});

app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const query = `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`;

        db.run(query, [email, hashedPassword, 'user'], function(err) {
            if (err) {
                return res.status(500).json({ error: "Erreur lors de l'inscription" });
            }

            res.status(201).json({ message: "Utilisateur créé avec succès" });
        });
    } catch (error) {
        res.status(500).json({ error: "Erreur serveur lors de la création du compte" });
    }
});

app.post('/api/auth/login', loginLimiter, (req, res) => {

    const { email, password } = req.body;

    const query = `SELECT * FROM users WHERE email = ?`;

    db.get(query, [email], async (err, user) => {

        if (err) {
            return res.status(500).json({ error: "Erreur serveur" });
        }

        if (!user) {
            return res.status(401).json({ error: "Identifiants incorrects" });
        }

        try {

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.status(401).json({ error: "Identifiants incorrects" });
            }

            const payload = {
                id: user.id,
                email: user.email,
                role: user.role
            };

            const token = jwt.sign(
                payload,
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            delete user.password;

            res.json({
                user: user,
                token: token
            });

        } catch (error) {
            res.status(500).json({ error: "Erreur serveur" });
        }

    });

});
app.get("/api/notes", authMiddleware, (req, res) => {
  const query = "SELECT * FROM notes";

  db.all(query, [], (err, notes) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });

    res.json(notes);
  });
});

app.get('/api/users', authMiddleware, isAdmin, (req, res) => {
    const query = "SELECT id, email, role FROM users";

    db.all(query, [], (err, users) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });

        res.json(users);
    });
});

app.delete('/api/notes/:id', authMiddleware, (req, res) => {
       const noteId = req.params.id;
       const userId = req.user.id;
       const sql = `DELETE FROM notes WHERE id = ? AND user_id = ?`;
         db.run(sql, [noteId, userId], function(err) {
              if (err) {
                console.error("Erreur lors de la suppression:", err.message);
                return res.status(500).json({ message: "Erreur serveur lors de la suppression de la note" });
            }
            if (this.changes === 0) {
                return res.status(403).json ({message: "Suppression refusée : note introuvable ou non autorisée." });
            }
            return res.status(200).json({message: "Note supprimée avec succès."});
        });
    });

app.post("/api/notes", authMiddleware, (req, res) => {
  const { content } = req.body;
  const userId = req.user.id;

  if (!content) {
    return res.status(400).json({ error: "Le contenu de la note est obligatoire" });
  }
  const query = "INSERT INTO notes (content, user_id) VALUES (?, ?)";

  db.run(query, [content, userId], function (err) {
    if (err) {
      console.error("Erreur lors de l'ajout de la note :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.status(201).json({
      message: "Note ajoutée avec succès",
      note: {
        id: this.lastID,
        content: content,
        user_id: userId
      }
    });
  });
});





const PORT = 3000;

app.listen(PORT, () => {
    console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});