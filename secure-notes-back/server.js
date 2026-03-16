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
        const query = `INSERT INTO users (email, password) VALUES (?, ?)`;

        db.run(query, [email, hashedPassword], function(err) {
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
                email: user.email
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
app.post('/api/notes', authMiddleware, (req, res) => {

    const { content } = req.body;

    const cleanContent = sanitizeHtml(content, {
        allowedTags: [],
        allowedAttributes: {}
    });

    const query = `INSERT INTO notes (content, authorId) VALUES (?, ?)`;

    db.run(query, [cleanContent, req.user.id], function(err) {

        if (err) {
            return res.status(500).json({ error: "Erreur serveur" });
        }

        res.json({
            message: "Note ajoutée",
            id: this.lastID
        });

    });

});


const PORT = 3000;

app.listen(PORT, () => {
    console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});