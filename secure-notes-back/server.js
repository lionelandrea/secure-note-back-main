require('dotenv').config();

const express = require('express');
const cors = require('cors');
const app = express();
const db = require('./database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(cors());
app.use(express.json());

const saltRounds = 10;
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    console.log("Tentative d'inscription pour :", email);

    if (!email || !password) {
        return res.status(400).json({ error: "Email et mot de passe requis" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const query = `INSERT INTO users (email, password) VALUES (?, ?)`;

        db.run(query, [email, hashedPassword], function (err) {
            if (err) {
                console.error("Erreur base de données :", err.message);
                return res.status(500).json({ error: "Erreur lors de l'inscription" });
            }

            res.status(201).json({ message: "Utilisateur créé avec succès" });
        });
    } catch (error) {
        console.error("Erreur lors du hachage :", error);
        res.status(500).json({ error: "Erreur serveur lors de la création du compte" });
    }
});
app.post('/api/auth/login', (req, res) => {
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
            console.error("Erreur lors de la comparaison :", error);
            res.status(500).json({ error: "Erreur serveur" });
        }

    });

});
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(403).json({ error: "Token manquant" });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.status(403).json({ error: "Format du token invalide" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: "Token invalide ou expiré" });
        }

        req.user = decoded;
        next();
    });
}

app.get('/api/notes', verifyToken, (req, res) => {
    console.log("Utilisateur connecté :", req.user);

    res.json([
        {
            id: 1,
            content: 'Ceci est une vraie route protégée par JWT !',
            authorId: req.user.id
        }
    ]);
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});