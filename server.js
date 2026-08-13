const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'khdamli-secret-key-2024';

// ========== EMAIL CONFIG ==========
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

let transporter;
if (EMAIL_USER && EMAIL_PASS) {
    transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS
        }
    });
}

// ========== CONNEXION MONGODB ATLAS ==========
const MONGO_URI = process.env.MONGODB_URI;

if (!MONGO_URI) {
    console.error('MONGO_URI manquant !');
    process.exit(1);
}

mongoose.connect(MONGO_URI)
    .then(() => console.log('Connecte a MongoDB Atlas'))
    .catch(err => {
        console.error('Erreur MongoDB:', err.message);
        process.exit(1);
    });

// ========== MODELES MONGOOSE ==========
const userSchema = new mongoose.Schema({
    id: { type: String, unique: true },
    nom: String,
    prenom: String,
    telephone: String,
    email: { type: String, unique: true },
    password: String,
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const requestSchema = new mongoose.Schema({
    id: { type: String, unique: true },
    userId: String,
    categorie: String,
    nomFamille: String,
    prenom: String,
    dateNaissance: String,
    telephone: String,
    passport: String,
    dateDelivrance: String,
    dateExpiration: String,
    centre: String,
    cas: String,
    personnesSupplementaires: { type: Array, default: [] },
    status: { type: String, default: 'en_cours' },
    createdAt: { type: Date, default: Date.now },
    appointmentDate: Date
});
const Request = mongoose.model('Request', requestSchema);

const otpSchema = new mongoose.Schema({
    email: String,
    otp: String,
    expires: Number
});
const Otp = mongoose.model('Otp', otpSchema);

// ========== MIDDLEWARES ==========
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ========== ROUTES PAGES HTML ==========
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/index.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/forgot-password.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'forgot-password.html'));
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// ========== MIDDLEWARE AUTH ==========
const authMiddleware = async (req, res, next) => {
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

// ========== ROUTES AUTH ==========

app.post('/api/register', async (req, res) => {
    const { nom, prenom, telephone, email, password } = req.body;
    const exist = await User.findOne({ email });
    if (exist) return res.status(400).json({ message: 'Email deja utilise' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
        id: uuidv4(),
        nom, prenom, telephone, email,
        password: hashedPassword
    });
    await user.save();
    res.status(201).json({ message: 'Inscription reussie', userId: user.id });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({
        token,
        user: { id: user.id, nom: user.nom, prenom: user.prenom, telephone: user.telephone, email: user.email }
    });
});

// Mot de passe oublié - Envoyer OTP par EMAIL
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Email non trouve' });

    if (!transporter) {
        return res.status(500).json({ message: 'Service email non configure' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await Otp.deleteMany({ email });
    await new Otp({ email, otp, expires: Date.now() + 600000 }).save();

    // Envoyer l'email
    try {
        await transporter.sendMail({
            from: '"Khdamli" <' + EMAIL_USER + '>',
            to: email,
            subject: 'Code de verification Khdamli',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;">
                    <h2 style="color: #1a5f9e;">Khdamli - Verification</h2>
                    <p>Bonjour,</p>
                    <p>Votre code de verification (OTP) est :</p>
                    <div style="background: #f0f0f0; padding: 20px; text-align: center; font-size: 28px; font-weight: bold; letter-spacing: 5px; border-radius: 8px;">
                        ${otp}
                    </div>
                    <p>Ce code expire dans <strong>10 minutes</strong>.</p>
                    <p style="color: #999; font-size: 12px;">Si vous n'avez pas demande ce code, ignorez cet email.</p>
                </div>
            `
        });
        res.json({ message: 'OTP envoye a votre email' });
    } catch (err) {
        console.error('Erreur email:', err);
        res.status(500).json({ message: 'Erreur lors de l\'envoi de l\'email' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    const stored = await Otp.findOne({ email, otp });
    if (!stored || Date.now() > stored.expires) {
        return res.status(400).json({ message: 'OTP invalide ou expire' });
    }
    res.json({ message: 'OTP verifie' });
});

app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const stored = await Otp.findOne({ email, otp });
    if (!stored) return res.status(400).json({ message: 'OTP invalide' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ email }, { password: hashed });
    await Otp.deleteMany({ email });
    res.json({ message: 'Mot de passe reinitialise' });
});

// ========== ROUTES DEMANDES ==========

app.post('/api/requests', authMiddleware, async (req, res) => {
    const request = new Request({
        id: uuidv4(),
        userId: req.user.userId,
        ...req.body,
        status: 'en_cours',
        appointmentDate: null
    });
    await request.save();
    res.status(201).json({ message: 'Demande creee', request });
});

app.get('/api/requests', authMiddleware, async (req, res) => {
    const userRequests = await Request.find({ userId: req.user.userId });
    res.json(userRequests);
});

app.post('/api/requests/:id/status', authMiddleware, async (req, res) => {
    const { status } = req.body;
    const update = { status };
    if (status === 'approuve') {
        update.appointmentDate = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000);
    }
    const request = await Request.findOneAndUpdate(
        { id: req.params.id, userId: req.user.userId },
        update,
        { new: true }
    );
    if (!request) return res.status(404).json({ message: 'Demande non trouvee' });
    res.json({ message: 'Statut mis a jour', request });
});

app.put('/api/profile', authMiddleware, async (req, res) => {
    const { telephone, password } = req.body;
    const updates = {};
    if (telephone) updates.telephone = telephone;
    if (password) updates.password = await bcrypt.hash(password, 10);

    const user = await User.findOneAndUpdate({ id: req.user.userId }, updates, { new: true });
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouve' });

    res.json({
        message: 'Profil mis a jour',
        user: { id: user.id, nom: user.nom, prenom: user.prenom, telephone: user.telephone, email: user.email }
    });
});

app.listen(PORT, () => {
    console.log('Serveur Khdamli demarre sur le port ' + PORT);
});
