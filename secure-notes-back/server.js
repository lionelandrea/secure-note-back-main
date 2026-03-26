require('dotenv').config();

const { body, validationResult } = require('express-validator');
const fs = require('fs');
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

function logSecurityEvent(message) {
    const logLine = `${new Date().toISOString()} - ${message}\n`;
    fs.appendFile('security.log', logLine, (err) => {
        if (err) {
            console.error('Erreur lors de l’écriture du log :', err);
        }
    });
}

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

app.post('/api/auth/register',[
        body('email')
            .isEmail()
            .withMessage('Format d\'email invalide'),
        body('password')
            .isLength({ min: 8 })
            .withMessage('Le mot de passe doit faire au moins 8 caractères')
    ],
     async (req, res) => {
         const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        
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

        if (user.lock_until && Date.now() < user.lock_until) {
            return res.status(423).json({
                error: "Compte temporairement verrouillé. Réessayez plus tard."
            });
        }

        try {
            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                const attempts = (user.login_attempts || 0) + 1;

                if (attempts >= 5) {
                    const lockUntil = Date.now() + 15 * 60 * 1000;

                    db.run(
                        `UPDATE users SET login_attempts = 0, lock_until = ? WHERE id = ?`,
                        [lockUntil, user.id],
                        (updateErr) => {
                            if (updateErr) {
                                return res.status(500).json({ error: "Erreur serveur" });
                            }

                            logSecurityEvent(`Compte verrouillé pour ${user.email}`);

                            return res.status(423).json({
                                error: "Compte verrouillé pendant 15 minutes."
                            });
                        }
                    );

                    return;
                }

                db.run(
                    `UPDATE users SET login_attempts = ? WHERE id = ?`,
                    [attempts, user.id],
                    (updateErr) => {
                        if (updateErr) {
                            return res.status(500).json({ error: "Erreur serveur" });
                        }

                        return res.status(401).json({ error: "Identifiants incorrects" });
                    }
                );

                return;
            }

            db.run(
                `UPDATE users SET login_attempts = 0, lock_until = NULL WHERE id = ?`,
                [user.id],
                (updateErr) => {
                    if (updateErr) {
                        return res.status(500).json({ error: "Erreur serveur" });
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

                    logSecurityEvent(`Connexion réussie pour ${user.email}`);

                    delete user.password;
                    delete user.login_attempts;
                    delete user.lock_until;

                    res.json({
                        user: user,
                        token: token
                    });
                }
            );

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

app.delete("/api/notes/:id", authMiddleware, (req, res) => {
    const noteId = req.params.id;
    const userId = req.user.id;
    const query = "DELETE FROM notes WHERE id = ? AND user_id = ?";

    db.run(query, [noteId, userId], function (err) {
        if (err) {
            return res.status(500).json({ error: "Erreur serveur" });
        }

        if (this.changes === 0) {
            return res.status(403).json({ error: "Suppression refusée : note introuvable ou non autorisée" });
        }

        res.status(200).json({ message: "Note supprimée avec succès" });
    });
});

app.post("/api/notes", authMiddleware, (req, res) => {
    const { content } = req.body;
    const userId = req.user.id;

    if (!content) {
        return res.status(400).json({ error: "Le contenu de la note est obligatoire" });
    }

    const cleanContent = sanitizeHtml(content, {
        allowedTags: [],
        allowedAttributes: {}
    });

    const query = "INSERT INTO notes (content, user_id) VALUES (?, ?)";

    db.run(query, [cleanContent, userId], function (err) {
        if (err) {
            return res.status(500).json({ error: "Erreur serveur" });
        }

        res.status(201).json({
            message: "Note ajoutée avec succès",
            note: {
                id: this.lastID,
                content: cleanContent,
                user_id: userId
            }
        });
    });
});

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});