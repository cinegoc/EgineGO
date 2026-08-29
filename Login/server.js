require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

app.use(cors());
app.use(express.json());

const STORAGE = process.env.STORAGE || "r2";
const JWT_SECRET = process.env.JWT_SECRET || "sua_chave_secreta";

// ================= MONGO DB =================
mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log('MongoDB Conectado'))
    .catch(err => console.error('Erro no MongoDB:', err));

// Schema de Usuário
const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    avatar: { type: String, default: "" },
    recoveryCode: { type: String, unique: true },
    profile: { type: mongoose.Schema.Types.Mixed, default: {} },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Schema de Mensagens do Chat de Grupo
const MessageSchema = new mongoose.Schema({
    roomId: { type: String, required: true },
    senderId: { type: String, required: true },
    senderName: { type: String, required: true },
    senderAvatar: { type: String, default: "" },
    message: { type: String, default: "" },
    type: { type: String, enum: ['text', 'image', 'link', 'action'], default: 'text' },
    extraData: { type: mongoose.Schema.Types.Mixed, default: {} }, // Para links, coordenadas, dados do player
    createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', MessageSchema);

// ================= STORAGE SETUP =================
const r2 = new S3Client({
    region: 'auto',
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID || "",
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || ""
    }
});

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({ storage: multer.memoryStorage() });

// Middleware de Autenticação HTTP
function auth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token ausente' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch {
        return res.status(401).json({ error: 'Token inválido' });
    }
}

// ================= ROTAS HTTP =================

// Registration
app.post('/register', async (req, res) => {
    const { email, password, name, avatar, profile = {} } = req.body;
    if (!email || !password || !name) {
        return res.status(400).json({ error: 'Preencha todos os campos' });
    }

    try {
        const exists = await User.findOne({ email });
        if (exists) return res.status(400).json({ error: 'Email já cadastrado' });

        const hash = await bcrypt.hash(password, 10);
        const recoveryCode = `SG-${Math.floor(1000 + Math.random()*9000)}-${Math.floor(1000 + Math.random()*9000)}`;

        const user = await User.create({
            email, password: hash, name, avatar, recoveryCode, profile
        });

        return res.json({
            success: true,
            recoveryCode,
            user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar, profile: user.profile }
        });
    } catch (err) {
        return res.status(500).json({ error: 'Erro interno' });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ error: 'Senha inválida' });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

        return res.json({
            token,
            user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar, profile: user.profile }
        });
    } catch (err) {
        return res.status(500).json({ error: 'Erro interno' });
    }
});

// Upload de Mídia / Avatar
app.post('/upload-avatar', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Arquivo não enviado' });

        if (STORAGE === "r2") {
            const ext = req.file.originalname.split('.').pop();
            const fileName = `avatars/${Date.now()}-${Math.random().toString(36).substring(2)}.${ext}`;

            await r2.send(new PutObjectCommand({
                Bucket: process.env.R2_BUCKET,
                Key: fileName,
                Body: req.file.buffer,
                ContentType: req.file.mimetype,
                CacheControl: 'public, max-age=31536000'
            }));

            return res.json({ success: true, url: `${process.env.R2_PUBLIC_URL}/${fileName}` });
        }

        if (STORAGE === "cloudinary") {
            const result = await new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream({ folder: "avatars" }, (err, result) => {
                    if (err) reject(err); else resolve(result);
                });
                streamifier.createReadStream(req.file.buffer).pipe(stream);
            });
            return res.json({ success: true, url: result.secure_url });
        }
    } catch (err) {
        return res.status(500).json({ error: 'Erro no upload' });
    }
});

// Historico de Mensagens do Grupo
app.get('/messages/:roomId', auth, async (req, res) => {
    try {
        const messages = await Message.find({ roomId: req.params.roomId })
            .sort({ createdAt: 1 })
            .limit(100);
        return res.json(messages);
    } catch (err) {
        return res.status(500).json({ error: 'Erro ao buscar mensagens' });
    }
});

// ================= WEBSOCKETS (SOCKET.IO) =================
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("Autenticação necessária"));
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.id;
        next();
    } catch (err) {
        next(new Error("Token inválido"));
    }
});

io.on('connection', (socket) => {
    console.log(`Usuário conectado via Socket: ${socket.userId}`);

    // Entrar em uma sala de chat do grupo
    socket.on('join_room', (roomId) => {
        socket.join(roomId);
        console.log(`Socket ${socket.id} entrou na sala ${roomId}`);
    });

    // Enviar mensagem de Chat (Texto, Links ou Ações do Jogo)
    socket.on('send_message', async (data) => {
        // data: { roomId, senderName, senderAvatar, message, type, extraData }
        try {
            const newMsg = await Message.create({
                roomId: data.roomId,
                senderId: socket.userId,
                senderName: data.senderName,
                senderAvatar: data.senderAvatar,
                message: data.message,
                type: data.type || 'text',
                extraData: data.extraData || {}
            });

            // Transmite a mensagem para todos os usuários na sala
            io.to(data.roomId).emit('receive_message', newMsg);
        } catch (err) {
            console.error("Erro ao salvar mensagem:", err);
        }
    });

    // Interações do Player em Tempo Real (ex: Posição, Links rápidos, Ações)
    socket.on('player_interaction', (data) => {
        // data: { roomId, action, payload }
        socket.to(data.roomId).emit('receive_player_interaction', {
            senderId: socket.userId,
            action: data.action,
            payload: data.payload
        });
    });

    // --- SINALIZAÇÃO WEBRTC (CALL DE VOZ) ---
    socket.on('call_user', (data) => {
        socket.to(data.roomId).emit('user_joined_call', { signal: data.signalData, from: socket.userId });
    });

    socket.on('answer_call', (data) => {
        io.to(data.to).emit('call_accepted', data.signal);
    });

    socket.on('ice_candidate', (data) => {
        socket.to(data.roomId).emit('ice_candidate', { candidate: data.candidate, from: socket.userId });
    });

    socket.on('disconnect', () => {
        console.log(`Socket desconectado: ${socket.id}`);
    });
});

// ================= INICIALIZAÇÃO (FLY.IO READY) =================
const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
