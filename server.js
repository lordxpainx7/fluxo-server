// ==================== SERVIDOR PONTE FLUXO ====================
// Hospedar no Render.com (Plano Gratuito)
// Este servidor atua como PONTE entre o App Usuário e o App Admin

const http = require('http');
const fs = require('fs');
const path = require('path');

// ==================== CONFIGURAÇÃO ====================
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'database.json');
const OFFLINE_LOG_FILE = path.join(__dirname, 'offline_log.json');

// ==================== BANCO DE DADOS ====================
let DB = {
    users: [],
    posts: [],
    stories: [],
    messages: [],
    reels: [],
    reports: [],
    notes: [],
    suspendedUsers: {},
    serverLog: [],
    adminConnected: false,
    lastAdminPing: null,
    requestCount: 0,
    startTime: Date.now()
};

// Log offline (ações que aconteceram enquanto admin estava offline)
let offlineLog = [];

// ==================== CARREGAR/SALVAR ====================
function loadDatabase() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            const data = fs.readFileSync(DATA_FILE, 'utf8');
            const parsed = JSON.parse(data);
            DB = { ...DB, ...parsed };
            console.log(`📦 DB carregado: ${DB.users.length} usuários, ${DB.posts.length} posts`);
        } else {
            console.log('📦 Novo banco de dados criado');
            saveDatabase();
        }
    } catch (error) {
        console.error('❌ Erro ao carregar DB:', error.message);
    }
    
    // Carregar log offline
    try {
        if (fs.existsSync(OFFLINE_LOG_FILE)) {
            const data = fs.readFileSync(OFFLINE_LOG_FILE, 'utf8');
            offlineLog = JSON.parse(data) || [];
            console.log(`📋 Log offline carregado: ${offlineLog.length} ações pendentes`);
        }
    } catch (error) {
        console.error('❌ Erro ao carregar log offline:', error.message);
        offlineLog = [];
    }
}

function saveDatabase() {
    try {
        const dataToSave = {
            users: DB.users,
            posts: DB.posts,
            stories: DB.stories,
            messages: DB.messages,
            reels: DB.reels,
            reports: DB.reports,
            notes: DB.notes,
            suspendedUsers: DB.suspendedUsers,
            serverLog: DB.serverLog.slice(0, 1000),
            adminConnected: DB.adminConnected,
            lastAdminPing: DB.lastAdminPing,
            requestCount: DB.requestCount,
            startTime: DB.startTime
        };
        fs.writeFileSync(DATA_FILE, JSON.stringify(dataToSave, null, 2), 'utf8');
    } catch (error) {
        console.error('❌ Erro ao salvar DB:', error.message);
    }
}

function saveOfflineLog() {
    try {
        fs.writeFileSync(OFFLINE_LOG_FILE, JSON.stringify(offlineLog, null, 2), 'utf8');
    } catch (error) {
        console.error('❌ Erro ao salvar log offline:', error.message);
    }
}

// ==================== LIMPEZA ====================
function cleanExpiredData() {
    const now = Date.now();
    
    // Stories (24h)
    DB.stories = DB.stories.filter(s => s.expiresAt > now);
    
    // Notes (20h)
    DB.notes = DB.notes.filter(n => n.expiresAt > now);
    
    // Suspensões expiradas
    Object.keys(DB.suspendedUsers).forEach(userId => {
        const s = DB.suspendedUsers[userId];
        if (s.until && s.until < now) {
            delete DB.suspendedUsers[userId];
            console.log(`✅ Suspensão expirada removida: ${userId}`);
        }
    });
    
    saveDatabase();
}

// ==================== API ====================
function processRequest(action, payload) {
    DB.requestCount++;
    
    // Verificar suspensão do usuário
    if (payload && payload.userId) {
        const suspension = DB.suspendedUsers[payload.userId];
        if (suspension) {
            if (!suspension.until || suspension.until > Date.now()) {
                return {
                    success: false,
                    error: 'Conta suspensa: ' + (suspension.reason || 'Violação dos termos'),
                    suspended: true
                };
            }
        }
    }
    
    // Registrar no log offline se admin não estiver conectado
    if (!DB.adminConnected && action !== 'adminPing' && action !== 'ping') {
        offlineLog.push({
            action,
            payload,
            timestamp: Date.now()
        });
        if (offlineLog.length > 10000) offlineLog = offlineLog.slice(-10000);
        saveOfflineLog();
    }
    
    console.log(`📡 ${action} - ${payload?.username || payload?.userId || 'system'}`);
    
    // ==================== HANDLERS ====================
    const handlers = {
        // ========== AUTENTICAÇÃO ==========
        register: () => {
            const { username, password, avatar, avatarType, bio } = payload;
            if (!username || !password) return { success: false, error: 'Dados incompletos' };
            if (username.length < 3 || password.length < 3) return { success: false, error: 'Mínimo 3 caracteres' };
            if (DB.users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
                return { success: false, error: 'Usuário já existe' };
            }
            const newUser = {
                id: 'u_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
                username,
                password,
                avatar: avatar || 'default',
                avatarType: avatarType || 'emoji',
                bio: bio || '',
                accountType: 'public',
                followers: [],
                following: [],
                followRequests: [],
                savedPosts: [],
                archivedPosts: [],
                drafts: [],
                createdAt: Date.now(),
                interests: []
            };
            DB.users.push(newUser);
            saveDatabase();
            console.log(`👤 Novo usuário: ${username}`);
            return { success: true, user: { ...newUser, password: undefined } };
        },
        
        login: () => {
            const { username, password } = payload;
            const user = DB.users.find(u =>
                u.username.toLowerCase() === username.toLowerCase() && u.password === password
            );
            if (!user) return { success: false, error: 'Credenciais inválidas' };
            
            const suspension = DB.suspendedUsers[user.id];
            if (suspension && (!suspension.until || suspension.until > Date.now())) {
                return {
                    success: false,
                    error: 'Conta suspensa: ' + (suspension.reason || 'Violação'),
                    suspended: true
                };
            }
            
            console.log(`🔑 Login: ${username}`);
            return { success: true, user: { ...user, password: undefined } };
        },
        
        // ========== PERFIL ==========
        updateProfile: () => {
            const { userId, username, avatar, avatarType, bio, accountType } = payload;
            const user = DB.users.find(u => u.id === userId);
            if (!user) return { success: false, error: 'Usuário não encontrado' };
            if (username) user.username = username;
            if (avatar) user.avatar = avatar;
            if (avatarType) user.avatarType = avatarType;
            if (bio !== undefined) user.bio = bio.substring(0, 200);
            if (accountType) user.accountType = accountType;
            saveDatabase();
            return { success: true, user: { ...user, password: undefined } };
        },
        
        getUserProfile: () => {
            const { userId, requesterId } = payload;
            const user = DB.users.find(u => u.id === userId);
            if (!user) return { success: false, error: 'Usuário não encontrado' };
            
            const isOwner = requesterId === userId;
            const isFollowing = user.followers && user.followers.includes(requesterId);
            const isPrivate = user.accountType === 'private';
            
            let posts = [];
            if (isOwner) {
                posts = DB.posts.filter(p => p.userId === userId && !p.archived);
            } else if (!isPrivate || isFollowing) {
                posts = DB.posts.filter(p => p.userId === userId && !p.archived);
            }
            
            return {
                success: true,
                profile: { ...user, password: undefined },
                posts: posts.slice(0, 50),
                isPrivate: isPrivate && !isOwner && !isFollowing
            };
        },
        
        // ========== SOCIAL ==========
        followUser: () => {
            const { userId, targetUserId } = payload;
            const user = DB.users.find(u => u.id === userId);
            const target = DB.users.find(u => u.id === targetUserId);
            if (!user || !target) return { success: false };
            
            if (target.accountType === 'private') {
                if (!target.followRequests) target.followRequests = [];
                if (!target.followRequests.includes(userId)) {
                    target.followRequests.push(userId);
                }
                saveDatabase();
                return { success: true, status: 'requested' };
            } else {
                if (!user.following) user.following = [];
                if (!target.followers) target.followers = [];
                if (!user.following.includes(targetUserId)) {
                    user.following.push(targetUserId);
                    target.followers.push(userId);
                }
                saveDatabase();
                const isMutual = target.following && target.following.includes(userId);
                return { success: true, status: isMutual ? 'mutual' : 'following' };
            }
        },
        
        unfollowUser: () => {
            const { userId, targetUserId } = payload;
            const user = DB.users.find(u => u.id === userId);
            const target = DB.users.find(u => u.id === targetUserId);
            if (user && user.following) {
                user.following = user.following.filter(id => id !== targetUserId);
            }
            if (target && target.followers) {
                target.followers = target.followers.filter(id => id !== userId);
            }
            saveDatabase();
            return { success: true };
        },
        
        // ========== POSTS ==========
        createPost: () => {
            const post = {
                id: 'p_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
                userId: payload.userId,
                username: payload.username,
                avatar: payload.avatar,
                avatarType: payload.avatarType,
                content: payload.content || '',
                mediaBase64: payload.mediaBase64 || null,
                mediaType: payload.mediaType || null,
                hashtags: payload.hashtags || [],
                likes: [],
                comments: [],
                reposts: [],
                saves: [],
                archived: false,
                timestamp: Date.now(),
                originalPostId: null,
                originalUsername: null,
                originalAvatar: null
            };
            DB.posts.unshift(post);
            if (DB.posts.length > 2000) DB.posts = DB.posts.slice(0, 2000);
            saveDatabase();
            return { success: true, post };
        },
        
        getPosts: () => {
            let posts = [...DB.posts].sort((a, b) => b.timestamp - a.timestamp);
            return { success: true, posts: posts.slice(0, 100) };
        },
        
        likePost: () => {
            const post = DB.posts.find(p => p.id === payload.postId);
            if (post) {
                if (!post.likes) post.likes = [];
                const idx = post.likes.indexOf(payload.userId);
                if (idx === -1) {
                    post.likes.push(payload.userId);
                } else {
                    post.likes.splice(idx, 1);
                }
                saveDatabase();
                return { success: true, likes: post.likes.length, liked: idx === -1 };
            }
            return { success: false, error: 'Post não encontrado' };
        },
        
        commentPost: () => {
            const post = DB.posts.find(p => p.id === payload.postId);
            if (post) {
                if (!post.comments) post.comments = [];
                post.comments.push({
                    id: 'c_' + Date.now(),
                    userId: payload.userId,
                    username: payload.username,
                    avatar: payload.avatar,
                    avatarType: payload.avatarType,
                    content: payload.content,
                    timestamp: Date.now(),
                    replies: [],
                    likes: []
                });
                saveDatabase();
                return { success: true };
            }
            return { success: false, error: 'Post não encontrado' };
        },
        
        replyComment: () => {
            const post = DB.posts.find(p => p.id === payload.postId);
            if (post) {
                const comment = post.comments.find(c => c.id === payload.commentId);
                if (comment) {
                    if (!comment.replies) comment.replies = [];
                    comment.replies.push({
                        id: 'cr_' + Date.now(),
                        userId: payload.userId,
                        username: payload.username,
                        avatar: payload.avatar,
                        avatarType: payload.avatarType,
                        content: payload.content,
                        timestamp: Date.now()
                    });
                    saveDatabase();
                }
            }
            return { success: true };
        },
        
        repost: () => {
            const original = DB.posts.find(p => p.id === payload.originalPostId);
            if (original) {
                const repost = {
                    ...original,
                    id: 'p_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
                    userId: payload.userId,
                    username: payload.username,
                    avatar: payload.avatar,
                    avatarType: payload.avatarType,
                    originalPostId: payload.originalPostId,
                    originalUsername: original.username,
                    originalAvatar: original.avatar,
                    likes: [],
                    comments: [],
                    reposts: [],
                    saves: [],
                    timestamp: Date.now()
                };
                if (!original.reposts) original.reposts = [];
                original.reposts.push(payload.userId);
                DB.posts.unshift(repost);
                saveDatabase();
                return { success: true };
            }
            return { success: false, error: 'Post original não encontrado' };
        },
        
        deletePost: () => {
            const idx = DB.posts.findIndex(p => p.id === payload.postId && p.userId === payload.userId);
            if (idx !== -1) {
                DB.posts.splice(idx, 1);
                saveDatabase();
                return { success: true };
            }
            return { success: false, error: 'Post não encontrado ou sem permissão' };
        },
        
        reportPost: () => {
            const report = {
                id: 'r_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
                postId: payload.postId,
                reportedBy: payload.reportedBy,
                reason: payload.reason,
                timestamp: Date.now(),
                resolved: false,
                resolution: null,
                resolvedAt: null
            };
            DB.reports.unshift(report);
            saveDatabase();
            return { success: true, message: 'Denúncia registrada' };
        },
        
        savePost: () => {
            const user = DB.users.find(u => u.id === payload.userId);
            if (user) {
                if (!user.savedPosts) user.savedPosts = [];
                if (user.savedPosts.includes(payload.postId)) {
                    user.savedPosts = user.savedPosts.filter(id => id !== payload.postId);
                    saveDatabase();
                    return { success: true, saved: false, message: 'Removido dos salvos' };
                } else {
                    user.savedPosts.push(payload.postId);
                    saveDatabase();
                    return { success: true, saved: true, message: 'Salvo!' };
                }
            }
            return { success: false };
        },
        
        getSavedPosts: () => {
            const user = DB.users.find(u => u.id === payload.userId);
            const saved = user && user.savedPosts ? DB.posts.filter(p => user.savedPosts.includes(p.id)) : [];
            return { success: true, posts: saved };
        },
        
        saveDraft: () => {
            const user = DB.users.find(u => u.id === payload.userId);
            if (user) {
                if (!user.drafts) user.drafts = [];
                user.drafts.unshift({
                    id: 'd_' + Date.now(),
                    content: payload.content,
                    mediaBase64: payload.mediaBase64,
                    mediaType: payload.mediaType,
                    hashtags: payload.hashtags,
                    timestamp: Date.now()
                });
                if (user.drafts.length > 20) user.drafts = user.drafts.slice(0, 20);
                saveDatabase();
            }
            return { success: true };
        },
        
        getDrafts: () => {
            const user = DB.users.find(u => u.id === payload.userId);
            return { success: true, drafts: user?.drafts || [] };
        },
        
        archivePost: () => {
            const post = DB.posts.find(p => p.id === payload.postId && p.userId === payload.userId);
            if (post) {
                post.archived = true;
                saveDatabase();
                return { success: true };
            }
            return { success: false };
        },
        
        getArchivedPosts: () => {
            const user = DB.users.find(u => u.id === payload.userId);
            const posts = user ? DB.posts.filter(p => p.userId === payload.userId && p.archived) : [];
            return { success: true, posts };
        },
        
        // ========== STORIES ==========
        createStory: () => {
            const story = {
                id: 's_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
                userId: payload.userId,
                username: payload.username,
                avatar: payload.avatar,
                avatarType: payload.avatarType,
                mediaBase64: payload.mediaBase64,
                mediaType: payload.mediaType,
                views: [],
                timestamp: Date.now(),
                expiresAt: Date.now() + 86400000 // 24 horas
            };
            DB.stories.unshift(story);
            DB.stories = DB.stories.filter(s => s.expiresAt > Date.now());
            saveDatabase();
            return { success: true, story };
        },
        
        getStories: () => {
            DB.stories = DB.stories.filter(s => s.expiresAt > Date.now());
            saveDatabase();
            return { success: true, stories: DB.stories.slice(0, 100) };
        },
        
        // ========== MENSAGENS ==========
        sendMessage: () => {
            const msg = {
                id: 'm_' + Date.now(),
                fromUserId: payload.fromUserId,
                fromUsername: payload.fromUsername,
                toUserId: payload.toUserId,
                content: payload.content || '',
                mediaBase64: payload.mediaBase64 || null,
                mediaType: payload.mediaType || null,
                replyTo: payload.replyTo || null,
                read: false,
                timestamp: Date.now()
            };
            DB.messages.push(msg);
            if (DB.messages.length > 5000) DB.messages = DB.messages.slice(-5000);
            saveDatabase();
            return { success: true, message: msg };
        },
        
        getMessages: () => {
            const messages = DB.messages
                .filter(m =>
                    (m.fromUserId === payload.userId && m.toUserId === payload.otherUserId) ||
                    (m.fromUserId === payload.otherUserId && m.toUserId === payload.userId)
                )
                .sort((a, b) => a.timestamp - b.timestamp)
                .slice(-200);
            
            // Marcar como lidas
            DB.messages.forEach(m => {
                if (m.toUserId === payload.userId && m.fromUserId === payload.otherUserId) {
                    m.read = true;
                }
            });
            saveDatabase();
            return { success: true, messages };
        },
        
        getConversations: () => {
            const userMsgs = DB.messages.filter(m =>
                m.fromUserId === payload.userId || m.toUserId === payload.userId
            );
            const conversations = {};
            userMsgs.forEach(m => {
                const otherId = m.fromUserId === payload.userId ? m.toUserId : m.fromUserId;
                if (!conversations[otherId] || conversations[otherId].timestamp < m.timestamp) {
                    const otherUser = DB.users.find(u => u.id === otherId);
                    conversations[otherId] = {
                        userId: otherId,
                        username: otherUser?.username || 'Desconhecido',
                        avatar: otherUser?.avatar || 'default',
                        avatarType: otherUser?.avatarType || 'emoji',
                        lastMessage: (m.content || '[Mídia]').substring(0, 30),
                        unread: m.toUserId === payload.userId && !m.read,
                        timestamp: m.timestamp
                    };
                }
            });
            return {
                success: true,
                conversations: Object.values(conversations).sort((a, b) => b.timestamp - a.timestamp)
            };
        },
        
        // ========== NOTES ==========
        createNote: () => {
            if (DB.notes.find(n => n.userId === payload.userId && n.expiresAt > Date.now())) {
                return { success: false, error: 'Já tem uma nota ativa' };
            }
            const note = {
                id: 'n_' + Date.now(),
                userId: payload.userId,
                username: payload.username,
                avatar: payload.avatar,
                avatarType: payload.avatarType,
                content: payload.content || '',
                timestamp: Date.now(),
                expiresAt: Date.now() + 72000000 // 20 horas
            };
            DB.notes.unshift(note);
            saveDatabase();
            return { success: true };
        },
        
        getNotes: () => {
            DB.notes = DB.notes.filter(n => n.expiresAt > Date.now());
            saveDatabase();
            return { success: true, notes: DB.notes };
        },
        
        deleteNote: () => {
            DB.notes = DB.notes.filter(n => !(n.id === payload.noteId && n.userId === payload.userId));
            saveDatabase();
            return { success: true };
        },
        
        // ========== REELS ==========
        createReel: () => {
            const reel = {
                id: 'rl_' + Date.now(),
                userId: payload.userId,
                username: payload.username,
                avatar: payload.avatar,
                avatarType: payload.avatarType,
                content: payload.content || '',
                videoBase64: payload.videoBase64,
                hashtags: payload.hashtags || [],
                likes: [],
                comments: [],
                shares: [],
                views: [],
                timestamp: Date.now()
            };
            DB.reels.unshift(reel);
            if (DB.reels.length > 500) DB.reels = DB.reels.slice(0, 500);
            saveDatabase();
            return { success: true };
        },
        
        getReels: () => {
            return { success: true, reels: DB.reels.slice(0, 50) };
        },
        
        // ========== SEARCH ==========
        search: () => {
            const query = (payload.query || '').toLowerCase();
            const results = {
                users: DB.users
                    .filter(u => u.username.toLowerCase().includes(query))
                    .slice(0, 20)
                    .map(u => ({
                        id: u.id,
                        username: u.username,
                        avatar: u.avatar,
                        avatarType: u.avatarType,
                        bio: u.bio
                    })),
                posts: DB.posts
                    .filter(p =>
                        p.content && p.content.toLowerCase().includes(query) ||
                        p.hashtags && p.hashtags.some(h => h.toLowerCase().includes(query))
                    )
                    .slice(0, 20)
            };
            return { success: true, results };
        },
        
        // ========== ADMIN ==========
        adminPing: () => {
            DB.adminConnected = true;
            DB.lastAdminPing = Date.now();
            
            // Retornar log offline acumulado
            const pendingLog = [...offlineLog];
            offlineLog = [];
            saveOfflineLog();
            saveDatabase();
            
            return {
                success: true,
                pendingLog,
                stats: {
                    users: DB.users.length,
                    posts: DB.posts.length,
                    reports: DB.reports.filter(r => !r.resolved).length,
                    suspended: Object.keys(DB.suspendedUsers).length,
                    stories: DB.stories.filter(s => s.expiresAt > Date.now()).length,
                    messages: DB.messages.length
                }
            };
        },
        
        adminGetAllReports: () => {
            return { success: true, reports: DB.reports.sort((a, b) => b.timestamp - a.timestamp) };
        },
        
        adminGetAllUsers: () => {
            const users = DB.users.map(u => ({
                id: u.id,
                username: u.username,
                avatar: u.avatar,
                avatarType: u.avatarType,
                bio: u.bio,
                accountType: u.accountType,
                followersCount: u.followers ? u.followers.length : 0,
                postsCount: DB.posts.filter(p => p.userId === u.id).length,
                createdAt: u.createdAt,
                isSuspended: !!DB.suspendedUsers[u.id],
                suspensionInfo: DB.suspendedUsers[u.id] || null
            }));
            return { success: true, users };
        },
        
        ping: () => {
            return {
                success: true,
                timestamp: Date.now(),
                uptime: Math.floor((Date.now() - DB.startTime) / 1000),
                requestCount: DB.requestCount,
                adminConnected: DB.adminConnected
            };
        }
    };
    
    // Executar handler correspondente
    if (handlers[action]) {
        return handlers[action]();
    }
    
    // Handlers simples (ações admin)
    if (action === 'adminDeletePost' || action === 'adminDeleteUser' ||
        action === 'adminSuspendUser' || action === 'adminUnsuspendUser' ||
        action === 'adminResolveReport') {
        // Apenas registrar e retornar sucesso
        // O processamento real é feito no app admin
        console.log(`📋 Ação admin registrada: ${action}`);
        return { success: true, message: 'Ação registrada' };
    }
    
    return { success: false, error: 'Ação não encontrada: ' + action };
}

// ==================== SERVIDOR HTTP ====================
const server = http.createServer((req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');
    
    // Preflight
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    // Rota da API
    if (req.url === '/api' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                const { action, payload } = JSON.parse(body);
                const result = processRequest(action, payload || {});
                res.writeHead(200);
                res.end(JSON.stringify(result));
            } catch (error) {
                res.writeHead(400);
                res.end(JSON.stringify({ success: false, error: 'JSON inválido' }));
            }
        });
        return;
    }
    
    // Rota de health check
    if (req.url === '/ping' || req.url === '/') {
        res.writeHead(200);
        res.end(JSON.stringify({
            success: true,
            status: 'online',
            timestamp: Date.now(),
            uptime: Math.floor((Date.now() - DB.startTime) / 1000),
            users: DB.users.length,
            posts: DB.posts.length,
            adminConnected: DB.adminConnected
        }));
        return;
    }
    
    // 404
    res.writeHead(404);
    res.end(JSON.stringify({ success: false, error: 'Rota não encontrada' }));
});

// ==================== VERIFICAÇÕES PERIÓDICAS ====================
// Verificar se admin está conectado
setInterval(() => {
    if (DB.lastAdminPing && Date.now() - DB.lastAdminPing > 30000) {
        DB.adminConnected = false;
    }
    cleanExpiredData();
}, 15000);

// ==================== INICIAR ====================
loadDatabase();
cleanExpiredData();

server.listen(PORT, '0.0.0.0', () => {
    console.log('═══════════════════════════════════');
    console.log('🔥 FLUXO SERVER PONTE ONLINE!');
    console.log('📡 Porta:', PORT);
    console.log('🌐 API:', `http://0.0.0.0:${PORT}/api`);
    console.log('👥 Usuários:', DB.users.length);
    console.log('📝 Posts:', DB.posts.length);
    console.log('📋 Log offline:', offlineLog.length, 'ações');
    console.log('═══════════════════════════════════');
});

module.exports = server;
