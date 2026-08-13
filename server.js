const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'khdamli-secret-key-2024';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Base de données en mémoire
const users = [];
const requests = [];
const otps = {};

// Middleware d'authentification
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Token manquant' });
    
    try {
        const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token invalide' });
    }
};

// ==================== ROUTES AUTH ====================

// Inscription
app.post('/api/register', async (req, res) => {
    const { nom, prenom, telephone, email, password } = req.body;
    
    if (users.find(u => u.email === email)) {
        return res.status(400).json({ message: 'Email déjà utilisé' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
        id: uuidv4(),
        nom,
        prenom,
        telephone,
        email,
        password: hashedPassword,
        createdAt: new Date()
    };
    
    users.push(user);
    res.status(201).json({ message: 'Inscription réussie', userId: user.id });
});

// Connexion
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }
    
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, nom: user.nom, prenom: user.prenom, telephone: user.telephone, email: user.email } });
});

// Demander OTP
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    const user = users.find(u => u.email === email);
    
    if (!user) return res.status(404).json({ message: 'Email non trouvé' });
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = { otp, expires: Date.now() + 600000 }; // 10 minutes
    
    res.json({ message: 'OTP envoyé', otp }); // En production, envoyer par email
});

// Vérifier OTP
app.post('/api/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    const stored = otps[email];
    
    if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
        return res.status(400).json({ message: 'OTP invalide ou expiré' });
    }
    
    res.json({ message: 'OTP vérifié' });
});

// Réinitialiser mot de passe
app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const stored = otps[email];
    
    if (!stored || stored.otp !== otp) {
        return res.status(400).json({ message: 'OTP invalide' });
    }
    
    const user = users.find(u => u.email === email);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });
    
    user.password = await bcrypt.hash(newPassword, 10);
    delete otps[email];
    
    res.json({ message: 'Mot de passe réinitialisé' });
});

// ==================== ROUTES DEMANDES ====================

// Créer une demande
app.post('/api/requests', authMiddleware, (req, res) => {
    const request = {
        id: uuidv4(),
        userId: req.user.userId,
        ...req.body,
        status: 'en_cours',
        createdAt: new Date(),
        appointmentDate: null
    };
    
    requests.push(request);
    res.status(201).json({ message: 'Demande créée', request });
});

// Récupérer les demandes de l'utilisateur
app.get('/api/requests', authMiddleware, (req, res) => {
    const userRequests = requests.filter(r => r.userId === req.user.userId);
    res.json(userRequests);
});

// Mettre à jour le statut (simulation)
app.post('/api/requests/:id/status', authMiddleware, (req, res) => {
    const { status } = req.body;
    const request = requests.find(r => r.id === req.params.id && r.userId === req.user.userId);
    
    if (!request) return res.status(404).json({ message: 'Demande non trouvée' });
    
    request.status = status;
    if (status === 'approuve') {
        request.appointmentDate = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000); // +60 jours
    }
    
    res.json({ message: 'Statut mis à jour', request });
});

// Mettre à jour profil
app.put('/api/profile', authMiddleware, async (req, res) => {
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });
    
    const { telephone, password } = req.body;
    if (telephone) user.telephone = telephone;
    if (password) user.password = await bcrypt.hash(password, 10);
    
    res.json({ message: 'Profil mis à jour', user: { id: user.id, nom: user.nom, prenom: user.prenom, telephone: user.telephone, email: user.email } });
});

app.listen(PORT, () => {
    console.log(`🚀 Serveur Khdamli démarré sur http://localhost:${PORT}`);
});
