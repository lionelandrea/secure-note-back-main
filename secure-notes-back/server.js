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
            console.error(err.message);
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

const adminDeleteLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            error: "Trop de suppressions administrateur. Veuillez patienter 15 minutes avant de réessayer."
        });
    }
});


app.post(
    '/api/auth/register',
    [
        body('email').isEmail().withMessage('Format d\'email invalide'),
        body('password').isLength({ min: 8 }).withMessage('Le mot de passe doit faire au moins 8 caractères')
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

            db.run(query, [email, hashedPassword, 'user'], function (err) {

                if (err) {
                    console.error(err.message);
                    return res.status(500).json({
                        error: "Une erreur interne du serveur est survenue."
                    });
                }

                res.status(201).json({
                    message: "Utilisateur créé avec succès"
                });

            });

        } catch (error) {

            console.error(error.message);

            res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });

        }

    }
);

app.post('/api/auth/login', loginLimiter, (req, res) => {

    const { email, password } = req.body;

    const query = `SELECT * FROM users WHERE email = ?`;

    db.get(query, [email], async (err, user) => {

        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
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
                                console.error(updateErr.message);
                                return res.status(500).json({
                                    error: "Une erreur interne du serveur est survenue."
                                });
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
                            console.error(updateErr.message);
                            return res.status(500).json({
                                error: "Une erreur interne du serveur est survenue."
                            });
                        }

                        return res.status(401).json({
                            error: "Identifiants incorrects"
                        });

                    }
                );

                return;
            }

            db.run(
                `UPDATE users SET login_attempts = 0, lock_until = NULL WHERE id = ?`,
                [user.id],
                (updateErr) => {

                    if (updateErr) {
                        console.error(updateErr.message);
                        return res.status(500).json({
                            error: "Une erreur interne du serveur est survenue."
                        });
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

            console.error(error.message);

            res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });

        }

    });

});

app.get("/api/notes", authMiddleware, (req, res) => {

    const query = "SELECT * FROM notes";

    db.all(query, [], (err, notes) => {

        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
        }

        res.json(notes);

    });

});

app.get('/api/users', authMiddleware, isAdmin, (req, res) => {

    const query = "SELECT id, email, role FROM users";

    db.all(query, [], (err, users) => {

        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
        }

        res.json(users);

    });

});

app.delete("/api/notes/:id", authMiddleware, (req, res) => {

    const noteId = req.params.id;
    const userId = req.user.id;

    const query = "DELETE FROM notes WHERE id = ? AND user_id = ?";

    db.run(query, [noteId, userId], function (err) {

        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
        }

        if (this.changes === 0) {
            return res.status(403).json({
                error: "Suppression refusée : note introuvable ou non autorisée"
            });
        }

        res.status(200).json({
            message: "Note supprimée avec succès"
        });

    });

});


app.post("/api/notes", authMiddleware, (req, res) => {

    const { content } = req.body;
    const userId = req.user.id;

    if (!content) {
        return res.status(400).json({
            error: "Le contenu de la note est obligatoire"
        });
    }

    const cleanContent = sanitizeHtml(content, {
        allowedTags: [],
        allowedAttributes: {}
    });

    const query = "INSERT INTO notes (content, user_id) VALUES (?, ?)";

    db.run(query, [cleanContent, userId], function (err) {

        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
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

//Mission 1: Modification du profil utilisateur
app.put(
    '/api/users/id',
    authMiddleware,
    [
        body('email').isMailtoURI().withMessage('Format d\'email invalide'),
    ],
    (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const userIdFromToken = req.user.id;
        const userIdFromParams = parseInt(req.params.id, 10);
        
        if (userIdFromToken !== userIdFromParams) {
            return res.status(403).json({
                error: "Accès refusé : vous ne pouvez modifier que votre profil"
            });
        }
    
        const { email, bio } = req.body;

        const query = `UPDATE users SET email = ?, bio = ? WHERE id = ?`;

        const cleanBio = sanitizeHtml(bio || '', {
            allowedTags: [],
            allowedAttributes: {}
        });

        db.run(query, [email, cleanBio, userIdFromToken], function (err) {

            if (err) {
                console.error(err.message);
                return res.status(500).json({
                    error: "Une erreur interne du serveur est survenue."
                });
            }

            res.status(200).json({
                message: "Profil mis à jour avec succès"
            });

        });

    }
);

//Mission 2: Liste complete des utilisateurs pour admin

app.get('/api/users', authMiddleware , isAdmin, (req, res) => {

    const query = "SELECT id, email, role FROM users";

    db.all(query, [], (err, users) => {

        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
        }

        res.json(users);

    });

});

//Mission 3: Suppression d un utilisateur par l admin , limitation , log

app.delete('/api/admin/users/:id', authMiddleware, isAdmin, adminDeleteLimiter, (req, res) => {
    const adminId = req.user.id;
    const userId = req.params.id;

    const deleteNotesQuery = `DELETE FROM notes WHERE user_id = ?`;
    const deleteUserQuery = `DELETE FROM users WHERE id = ?`;

    db.run(deleteNotesQuery, [userId], function (err) {
        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
        }

        logAdminAction(`l'Admin ${adminId} a supprimé  l'utilisateur ${userId}`);
        
        res.status(200).json({
            message: "Utilisateur supprimés avec succès."
        });
    });
});

//Mission 5: Lecture des logs de l admin
app.get('/api/admin/logs', authMiddleware, isAdmin, (req, res) => {
    fs.readFile('admin_actions.log', 'utf8', (err, data) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
        }

        const lines = data.split('\n').filter(line => line.trim() !== '');

        res.json(lines);
    });

});
app.delete('/api/users/user', authMiddleware, (req, res) => {
    const userId = req.user.id;

    const deleteNotesQuery = `DELETE FROM notes WHERE user_id = ?`;
    const deleteUserQuery = `DELETE FROM users WHERE id = ?`;

    db.run(deleteNotesQuery, [userId], function (err) {
        if (err) {
            console.error(err.message);
            return res.status(500).json({
                error: "Une erreur interne du serveur est survenue."
            });
        }

        db.run(deleteUserQuery, [userId], function (err) {
            if (err) {
                console.error(err.message);
                return res.status(500).json({
                    error: "Une erreur interne du serveur est survenue."
                });
            }

            res.clearCookie('jwt');

            res.status(200).json({
                message: "Votre compte et toutes vos données ont été supprimés avec succès."
            });
        });
    });
});

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});