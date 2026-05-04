const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'database.json');
const OFFLINE_LOG_FILE = path.join(__dirname, 'offline_log.json');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');
const AUDIT_FILE = path.join(__dirname, 'audit_log.json');

// ==================== ESTRUTURAS DE SEGURANÇA SUPREMAS ====================
let DB = {
    users: [], posts: [], stories: [], messages: [], reels: [],
    reports: [], notes: [], suspendedUsers: {}, serverLog: [],
    adminConnected: false, lastAdminPing: null,
    requestCount: 0, startTime: Date.now(),
    
    // SEGURANÇA NÍVEL DEUS SUPREMO
    ipBlacklist: {},
    ipRequests: {},
    userActions: {},
    spamPatterns: {},
    deviceFingerprints: {},
    vpnDetections: {},
    globalPostHash: {},
    commentHash: {},
    suspiciousAccounts: {},
    banHistory: [],
    sessionTokens: {},       // Tokens de sessão válidos
    rateLimitViolations: {}, // Violações de rate limit
    ddosProtection: {},      // Proteção DDoS
    requestSignatures: {},   // Assinaturas de requisições
    honeypotTriggers: {},    // Honeypots acionados
    blockedUserAgents: {},   // User Agents bloqueados
    originWhitelist: [],     // Origens permitidas
    csrfTokens: {},          // Tokens CSRF
    encryptionKeys: {}       // Chaves de criptografia
};

let offlineLog = [];
let globalBlacklist = { ips: [], fingerprints: [], patterns: [], userAgents: [] };
let auditLog = [];

// ==================== CONFIG DE SEGURANÇA SUPREMA ====================
const GOD_MODE_SUPREME = {
    // Anti-Spam
    maxPostsPerMinute: 2,
    maxPostsPerHour: 10,
    maxRepostsPerMinute: 1,
    maxRepostsTotal: 3,
    maxCommentsPerMinute: 3,
    maxIdenticalPosts: 1,
    maxIdenticalComments: 2,
    
    // Anti-Força Bruta
    maxLoginAttempts: 3,
    loginLockoutDuration: 900000, // 15 minutos
    maxPasswordResetAttempts: 2,
    
    // Anti-DDoS
    maxRequestsPerSecond: 10,
    maxRequestsPerMinute: 30,
    maxConcurrentConnections: 50,
    ddosThreshold: 100,       // Requisições/segundo para ativar proteção
    ddosBlockDuration: 3600000, // 1 hora
    
    // Anti-Injeção
    maxContentLength: 5000,   // Tamanho máximo do conteúdo
    maxMediaSize: 10485760,   // 10MB máximo para mídia
    blockedPatterns: [
        /<script[^>]*>/i,     // Script tags
        /<\/script>/i,        // Script closing
        /javascript:/i,       // JavaScript protocol
        /on\w+\s*=/i,         // Event handlers (onclick, onload)
        /<iframe[^>]*>/i,     // Iframes
        /<object[^>]*>/i,     // Objects
        /<embed[^>]*>/i,      // Embeds
        /eval\s*\(/i,         // Eval function
        /document\.cookie/i,  // Cookie theft
        /document\.write/i,   // Document write
        /XMLHttpRequest/i,    // XHR in content
        /fetch\s*\(/i,        // Fetch in content
        /WebSocket/i,         // WebSocket in content
        /localStorage/i,      // LocalStorage access
        /sessionStorage/i,    // SessionStorage access
        /alert\s*\(/i,        // Alert
        /prompt\s*\(/i,       // Prompt
        /confirm\s*\(/i,      // Confirm
        /\.innerHTML\s*=/i,   // innerHTML manipulation
        /\.outerHTML\s*=/i,   // outerHTML
        /String\.fromCharCode/i, // Obfuscated code
        /\\x[0-9a-f]{2}/i,    // Hex encoded
        /\\u[0-9a-f]{4}/i,    // Unicode encoded
        /&#x[0-9a-f]+;/i,     // HTML entities
        /base64,/i,           // Base64 in content (suspicious)
    ],
    
    // Anti-Tampering
    signatureSecret: crypto.randomBytes(32).toString('hex'),
    tokenExpiry: 3600000,     // 1 hora
    maxTokenUses: 100,
    
    // Penalidades
    spamWarningThreshold: 2,
    suspendDuration: 86400000,
    permaBanThreshold: 3,
    banDuration: Infinity,
    
    // Rate Limiting
    maxRequestsPerIP: 100,
    requestWindowMs: 60000,
    
    // VPN/Proxy
    vpnCheckEnabled: true,
    maxAccountsPerIP: 1,
    maxAccountsPerFingerprint: 1,
    
    // Honeypot
    honeypotEnabled: true,
    honeypotFieldName: 'website', // Campo invisível para bots
    honeypotBanDuration: 86400000,
};

// ==================== FUNÇÕES DE SEGURANÇA ====================

// Sanitização de entrada (anti-XSS/Injeção)
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    
    // Remover tags HTML
    let sanitized = input
        .replace(/<[^>]*>/g, '')           // Remove todas as tags HTML
        .replace(/&/g, '&amp;')            // Escapa &
        .replace(/</g, '&lt;')             // Escapa <
        .replace(/>/g, '&gt;')             // Escapa >
        .replace(/"/g, '&quot;')           // Escapa "
        .replace(/'/g, '&#x27;')           // Escapa '
        .replace(/\//g, '&#x2F;')          // Escapa /
        .replace(/\\/g, '&#x5C;')          // Escapa \
        .replace(/`/g, '&#x60;')           // Escapa `
        .replace(/\(/g, '&#40;')           // Escapa (
        .replace(/\)/g, '&#41;')           // Escapa )
        .replace(/\[/g, '&#91;')           // Escapa [
        .replace(/\]/g, '&#93;')           // Escapa ]
        .replace(/\{/g, '&#123;')          // Escapa {
        .replace(/\}/g, '&#125;');         // Escapa }
    
    return sanitized;
}

// Detecção de padrões maliciosos
function detectMaliciousContent(content) {
    if (!content) return { safe: true };
    
    for (const pattern of GOD_MODE_SUPREME.blockedPatterns) {
        if (pattern.test(content)) {
            return {
                safe: false,
                reason: 'Conteúdo malicioso detectado',
                pattern: pattern.toString(),
                severity: 'CRITICAL'
            };
        }
    }
    
    // Verificar tamanho
    if (content.length > GOD_MODE_SUPREME.maxContentLength) {
        return { safe: false, reason: 'Conteúdo muito longo', severity: 'HIGH' };
    }
    
    return { safe: true };
}

// Verificar injeção SQL (mesmo sem SQL, por segurança)
function detectSQLInjection(input) {
    const sqlPatterns = [
        /(\s|^)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|UNION|EXEC|EXECUTE)\s/i,
        /(\s|^)(OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/i,
        /--\s*$/,                              // SQL comment
        /\/\*[\s\S]*\*\//,                    // Block comment
        /;\s*(SELECT|INSERT|UPDATE|DELETE)/i,  // Multiple statements
        /'\s*OR\s*'1'?\s*=\s*'1/i,           // Classic injection
        /'\s*OR\s*1\s*=\s*1/i,               // Numeric injection
    ];
    
    for (const pattern of sqlPatterns) {
        if (pattern.test(input)) {
            return true;
        }
    }
    return false;
}

// Gerar token de sessão seguro
function generateSessionToken(userId, ip) {
    const tokenData = `${userId}|${ip}|${Date.now()}|${crypto.randomBytes(16).toString('hex')}`;
    const token = crypto.createHmac('sha256', GOD_MODE_SUPREME.signatureSecret)
        .update(tokenData)
        .digest('hex');
    
    DB.sessionTokens[token] = {
        userId: userId,
        ip: ip,
        createdAt: Date.now(),
        expiresAt: Date.now() + GOD_MODE_SUPREME.tokenExpiry,
        useCount: 0
    };
    
    return token;
}

// Validar token de sessão
function validateSessionToken(token, ip) {
    if (!token || !DB.sessionTokens[token]) return false;
    
    const session = DB.sessionTokens[token];
    
    // Verificar expiração
    if (Date.now() > session.expiresAt) {
        delete DB.sessionTokens[token];
        return false;
    }
    
    // Verificar IP (anti-hijacking)
    if (session.ip !== ip) {
        // Possível hijacking detectado
        auditLog.push({
            type: 'SESSION_HIJACK_ATTEMPT',
            token: token.substring(0, 10) + '...',
            originalIP: session.ip,
            attemptedIP: ip,
            timestamp: Date.now()
        });
        delete DB.sessionTokens[token];
        return false;
    }
    
    // Verificar uso excessivo
    session.useCount++;
    if (session.useCount > GOD_MODE_SUPREME.maxTokenUses) {
        delete DB.sessionTokens[token];
        return false;
    }
    
    return true;
}

// Proteção DDoS
function ddosProtection(ip) {
    const now = Date.now();
    
    if (!DB.ddosProtection[ip]) {
        DB.ddosProtection[ip] = {
            requests: [],
            blocked: false,
            blockUntil: null
        };
    }
    
    const protection = DB.ddosProtection[ip];
    
    // Verificar se está bloqueado
    if (protection.blocked && protection.blockUntil > now) {
        return { allowed: false, reason: 'DDoS protection active' };
    }
    
    // Limpar requisições antigas
    protection.requests = protection.requests.filter(t => now - t < 1000);
    
    // Adicionar requisição atual
    protection.requests.push(now);
    
    // Verificar threshold
    if (protection.requests.length > GOD_MODE_SUPREME.ddosThreshold) {
        protection.blocked = true;
        protection.blockUntil = now + GOD_MODE_SUPREME.ddosBlockDuration;
        
        // Adicionar à blacklist
        DB.ipBlacklist[ip] = {
            bannedAt: now,
            reason: 'DDoS attack detected',
            permanent: false,
            until: protection.blockUntil
        };
        
        auditLog.push({
            type: 'DDOS_ATTACK_DETECTED',
            ip: ip,
            requestRate: protection.requests.length,
            timestamp: now
        });
        
        return { allowed: false, reason: 'DDoS attack blocked' };
    }
    
    return { allowed: true };
}

// Verificar honeypot (campos invisíveis para bots)
function checkHoneypot(payload) {
    if (GOD_MODE_SUPREME.honeypotEnabled && payload) {
        // Se o campo honeypot estiver preenchido, é um bot
        if (payload[GOD_MODE_SUPREME.honeypotFieldName]) {
            return { isBot: true, reason: 'Honeypot triggered' };
        }
    }
    return { isBot: false };
}

// Verificar assinatura de requisição (anti-tampering)
function verifyRequestSignature(payload, signature, ip) {
    if (!signature) return false;
    
    const expectedSignature = crypto.createHmac('sha256', GOD_MODE_SUPREME.signatureSecret)
        .update(JSON.stringify(payload) + ip)
        .digest('hex');
    
    return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
    );
}

// Detectar race condition (múltiplas requisições simultâneas)
function detectRaceCondition(userId, action) {
    const now = Date.now();
    const key = `${userId}_${action}`;
    
    if (!DB.requestSignatures[key]) {
        DB.requestSignatures[key] = [];
    }
    
    // Limpar assinaturas antigas
    DB.requestSignatures[key] = DB.requestSignatures[key].filter(t => now - t < 100);
    
    // Se já tem uma requisição muito recente, é race condition
    if (DB.requestSignatures[key].length > 0) {
        const lastRequest = DB.requestSignatures[key][DB.requestSignatures[key].length - 1];
        if (now - lastRequest < 50) { // 50ms = suspeito
            return { raceCondition: true };
        }
    }
    
    DB.requestSignatures[key].push(now);
    return { raceCondition: false };
}

// Validar Content-Type e headers
function validateHeaders(req) {
    const contentType = req.headers['content-type'] || '';
    const userAgent = req.headers['user-agent'] || '';
    const origin = req.headers['origin'] || '';
    const referer = req.headers['referer'] || '';
    
    // Verificar Content-Type
    if (req.method === 'POST' && !contentType.includes('application/json')) {
        return { valid: false, reason: 'Invalid Content-Type' };
    }
    
    // Verificar User-Agent (bloquear bots conhecidos)
    const blockedAgents = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'java/', 'nmap'];
    const lowerAgent = userAgent.toLowerCase();
    
    for (const agent of blockedAgents) {
        if (lowerAgent.includes(agent)) {
            DB.blockedUserAgents[userAgent] = (DB.blockedUserAgents[userAgent] || 0) + 1;
            return { valid: false, reason: 'Bot detected' };
        }
    }
    
    // Verificar se User-Agent está vazio (suspeito)
    if (!userAgent || userAgent.length < 10) {
        return { valid: false, reason: 'Suspicious User-Agent' };
    }
    
    return { valid: true };
}

// Criptografar dados sensíveis
function encryptData(data) {
    const key = crypto.scryptSync(GOD_MODE_SUPREME.signatureSecret, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

// Descriptografar dados
function decryptData(encryptedData) {
    try {
        const parts = encryptedData.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        const key = crypto.scryptSync(GOD_MODE_SUPREME.signatureSecret, 'salt', 32);
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (e) {
        return null;
    }
}

// ==================== FUNÇÕES DE BANCO ====================
function loadDatabase() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
            DB = { ...DB, ...parsed };
            ensureSecurityStructures();
        }
    } catch (e) { console.error('DB Load Error:', e.message); }
    
    try {
        if (fs.existsSync(BLACKLIST_FILE)) {
            globalBlacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8'));
        }
    } catch (e) {}
    
    try {
        if (fs.existsSync(AUDIT_FILE)) {
            auditLog = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8')) || [];
        }
    } catch (e) {}
    
    try {
        if (fs.existsSync(OFFLINE_LOG_FILE)) {
            offlineLog = JSON.parse(fs.readFileSync(OFFLINE_LOG_FILE, 'utf8')) || [];
        }
    } catch (e) {}
}

function ensureSecurityStructures() {
    if (!DB.sessionTokens) DB.sessionTokens = {};
    if (!DB.rateLimitViolations) DB.rateLimitViolations = {};
    if (!DB.ddosProtection) DB.ddosProtection = {};
    if (!DB.requestSignatures) DB.requestSignatures = {};
    if (!DB.honeypotTriggers) DB.honeypotTriggers = {};
    if (!DB.blockedUserAgents) DB.blockedUserAgents = {};
    if (!DB.csrfTokens) DB.csrfTokens = {};
}

function saveDatabase() {
    try { fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2), 'utf8'); } catch (e) {}
}

function saveAuditLog() {
    try { fs.writeFileSync(AUDIT_FILE, JSON.stringify(auditLog.slice(-5000), null, 2), 'utf8'); } catch (e) {}
}

// ==================== API PRINCIPAL COM SEGURANÇA SUPREMA ====================
function processRequest(action, payload, reqIP, reqHeaders) {
    const now = Date.now();
    DB.requestCount++;
    
    // 🔒 CAMADA 1: Blacklist Global
    if (globalBlacklist.ips.includes(reqIP)) {
        auditLog.push({ type: 'BLACKLISTED_IP', ip: reqIP, action, timestamp: now });
        saveAuditLog();
        return { success: false, error: 'Access denied', code: 'BLACKLISTED' };
    }
    
    // 🔒 CAMADA 2: IP Banido
    if (DB.ipBlacklist[reqIP] && DB.ipBlacklist[reqIP].until > now) {
        return { success: false, error: 'IP banned', code: 'IP_BANNED' };
    }
    
    // 🔒 CAMADA 3: DDoS Protection
    const ddosCheck = ddosProtection(reqIP);
    if (!ddosCheck.allowed) {
        return { success: false, error: ddosCheck.reason, code: 'DDOS_BLOCKED' };
    }
    
    // 🔒 CAMADA 4: Rate Limiting
    if (!checkRateLimit(reqIP)) {
        return { success: false, error: 'Rate limit exceeded', code: 'RATE_LIMITED' };
    }
    
    // 🔒 CAMADA 5: Header Validation
    const headerCheck = validateHeaders({ method: 'POST', headers: reqHeaders });
    if (!headerCheck.valid) {
        return { success: false, error: headerCheck.reason, code: 'INVALID_HEADERS' };
    }
    
    // 🔒 CAMADA 6: Suspension Check
    if (payload && payload.userId) {
        const suspension = DB.suspendedUsers[payload.userId];
        if (suspension && (!suspension.until || suspension.until > now)) {
            return { success: false, error: 'Account suspended', code: 'SUSPENDED' };
        }
    }
    
    // 🔒 CAMADA 7: Honeypot
    if (payload) {
        const honeypotCheck = checkHoneypot(payload);
        if (honeypotCheck.isBot) {
            DB.honeypotTriggers[reqIP] = (DB.honeypotTriggers[reqIP] || 0) + 1;
            if (DB.honeypotTriggers[reqIP] > 3) {
                DB.ipBlacklist[reqIP] = { until: now + 86400000, reason: 'Bot detected' };
            }
            saveDatabase();
            return { success: false, error: 'Bot detected', code: 'HONEYPOT' };
        }
    }
    
    // 🔒 CAMADA 8: SQL Injection Detection
    if (payload) {
        const payloadStr = JSON.stringify(payload);
        if (detectSQLInjection(payloadStr)) {
            DB.ipBlacklist[reqIP] = { until: now + 86400000, reason: 'SQL Injection attempt' };
            saveDatabase();
            auditLog.push({ type: 'SQL_INJECTION', ip: reqIP, timestamp: now });
            saveAuditLog();
            return { success: false, error: 'Malicious request', code: 'INJECTION' };
        }
    }
    
    // 🔒 CAMADA 9: Content Sanitization
    if (payload) {
        if (payload.content) {
            const maliciousCheck = detectMaliciousContent(payload.content);
            if (!maliciousCheck.safe) {
                auditLog.push({ type: 'MALICIOUS_CONTENT', ip: reqIP, reason: maliciousCheck.reason, timestamp: now });
                saveAuditLog();
                return { success: false, error: maliciousCheck.reason, code: 'MALICIOUS' };
            }
            payload.content = sanitizeInput(payload.content);
        }
        if (payload.bio) {
            payload.bio = sanitizeInput(payload.bio);
        }
        if (payload.username) {
            payload.username = sanitizeInput(payload.username);
        }
    }
    
    // 🔒 CAMADA 10: Race Condition Detection
    if (payload && payload.userId && ['createPost', 'likePost', 'sendMessage'].includes(action)) {
        const raceCheck = detectRaceCondition(payload.userId, action);
        if (raceCheck.raceCondition) {
            return { success: false, error: 'Too many requests', code: 'RACE_CONDITION' };
        }
    }
    
    console.log(`📡 ${action} - ${payload?.username || 'anon'} - IP: ${reqIP}`);
    
    // ==================== HANDLERS ====================
    const handlers = {
        register: () => {
            const { username, password } = payload;
            if (!username || !password) return { success: false, error: 'Incomplete data' };
            if (username.length < 3 || password.length < 3) return { success: false, error: 'Too short' };
            
            // Verificar nome suspeito
            const spamNames = ['test', 'spam', 'bot', 'admin', 'root'];
            if (spamNames.some(n => username.toLowerCase().includes(n))) {
                return { success: false, error: 'Invalid username' };
            }
            
            if (DB.users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
                return { success: false, error: 'Username exists' };
            }
            
            const accountsFromIP = DB.users.filter(u => u.createdIP === reqIP).length;
            if (accountsFromIP >= 1) {
                return { success: false, error: 'Account limit reached' };
            }
            
            const newUser = {
                id: 'u_' + now + '_' + crypto.randomBytes(4).toString('hex'),
                username, password,
                avatar: payload.avatar || 'default',
                avatarType: payload.avatarType || 'emoji',
                bio: payload.bio || '',
                accountType: 'public',
                followers: [], following: [],
                savedPosts: [], drafts: [],
                createdAt: now, createdIP: reqIP,
                interests: []
            };
            
            DB.users.push(newUser);
            
            // Gerar token de sessão
            const token = generateSessionToken(newUser.id, reqIP);
            
            saveDatabase();
            return { success: true, user: { ...newUser, password: undefined }, token };
        },
        
        login: () => {
            const { username, password } = payload;
            
            // Verificar tentativas de login
            const loginKey = `login_${reqIP}`;
            if (!DB.rateLimitViolations[loginKey]) DB.rateLimitViolations[loginKey] = { count: 0, lastAttempt: 0 };
            
            const loginAttempts = DB.rateLimitViolations[loginKey];
            
            if (loginAttempts.count >= GOD_MODE_SUPREME.maxLoginAttempts) {
                if (now - loginAttempts.lastAttempt < GOD_MODE_SUPREME.loginLockoutDuration) {
                    return { success: false, error: 'Too many attempts. Try later.' };
                }
                loginAttempts.count = 0;
            }
            
            loginAttempts.count++;
            loginAttempts.lastAttempt = now;
            
            const user = DB.users.find(u =>
                u.username.toLowerCase() === username.toLowerCase() && u.password === password
            );
            
            if (!user) {
                saveDatabase();
                return { success: false, error: 'Invalid credentials' };
            }
            
            // Resetar tentativas
            loginAttempts.count = 0;
            
            // Gerar token
            const token = generateSessionToken(user.id, reqIP);
            
            saveDatabase();
            return { success: true, user: { ...user, password: undefined }, token };
        },
        
        createPost: () => {
            const post = {
                id: 'p_' + now + '_' + crypto.randomBytes(3).toString('hex'),
                ...payload,
                likes: [], comments: [], reposts: [], saves: [],
                timestamp: now, originalPostId: null
            };
            DB.posts.unshift(post);
            if (DB.posts.length > 2000) DB.posts = DB.posts.slice(0, 2000);
            saveDatabase();
            return { success: true, post };
        },
        
        getPosts: () => {
            return { success: true, posts: DB.posts.sort((a,b) => b.timestamp - a.timestamp).slice(0, 100) };
        },
        
        adminPing: () => {
            DB.adminConnected = true;
            DB.lastAdminPing = now;
            const pendingLog = [...offlineLog];
            offlineLog = [];
            saveDatabase();
            return {
                success: true, pendingLog,
                stats: {
                    users: DB.users.length, posts: DB.posts.length,
                    reports: (DB.reports||[]).filter(r=>!r.resolved).length,
                    suspended: Object.keys(DB.suspendedUsers).length,
                    bannedIPs: Object.keys(DB.ipBlacklist).length,
                    ddosBlocks: Object.values(DB.ddosProtection).filter(d=>d.blocked).length,
                    auditEntries: auditLog.length
                }
            };
        },
        
        adminGetAuditLog: () => {
            return { success: true, auditLog: auditLog.slice(-100) };
        },
        
        adminGetSecurityStats: () => {
            return {
                success: true,
                stats: {
                    totalBans: DB.banHistory.length,
                    activeBlocks: Object.keys(DB.ipBlacklist).length,
                    ddosAttacks: Object.values(DB.ddosProtection).filter(d=>d.blocked).length,
                    injectionAttempts: auditLog.filter(a=>a.type==='SQL_INJECTION').length,
                    maliciousContent: auditLog.filter(a=>a.type==='MALICIOUS_CONTENT').length,
                    honeypotTriggers: Object.values(DB.honeypotTriggers).reduce((a,b)=>a+b,0),
                    sessionHijackAttempts: auditLog.filter(a=>a.type==='SESSION_HIJACK_ATTEMPT').length,
                    rateLimitViolations: Object.keys(DB.rateLimitViolations).length
                }
            };
        },
        
        ping: () => ({
            success: true, timestamp: now,
            securityLevel: 'DEUS_SUPREMO',
            activeProtections: 10
        })
    };
    
    if (handlers[action]) return handlers[action]();
    return { success: false, error: 'Unknown action' };
}

// ==================== RATE LIMITING ====================
function checkRateLimit(ip) {
    const now = Date.now();
    if (!DB.ipRequests[ip]) DB.ipRequests[ip] = { requests: [], count: 0 };
    DB.ipRequests[ip].requests = DB.ipRequests[ip].requests.filter(t => now - t < 60000);
    DB.ipRequests[ip].requests.push(now);
    DB.ipRequests[ip].count++;
    return DB.ipRequests[ip].requests.length <= GOD_MODE_SUPREME.maxRequestsPerMinute;
}

// ==================== SERVER ====================
const server = http.createServer((req, res) => {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');
    
    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }
    
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    const reqHeaders = {
        'user-agent': req.headers['user-agent'] || '',
        'accept-language': req.headers['accept-language'] || '',
        'origin': req.headers['origin'] || '',
        'content-type': req.headers['content-type'] || ''
    };
    
    if (req.url === '/api' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                const { action, payload } = JSON.parse(body);
                const result = processRequest(action, payload || {}, clientIP, reqHeaders);
                res.writeHead(200);
                res.end(JSON.stringify(result));
            } catch (error) {
                res.writeHead(400);
                res.end(JSON.stringify({ success: false, error: 'Invalid JSON' }));
            }
        });
        return;
    }
    
    if (req.url === '/ping' || req.url === '/') {
        res.writeHead(200);
        res.end(JSON.stringify({
            success: true, status: 'online',
            securityLevel: 'DEUS_SUPREMO',
            timestamp: Date.now()
        }));
        return;
    }
    
    res.writeHead(404);
    res.end(JSON.stringify({ success: false, error: 'Not found' }));
});

// ==================== INIT ====================
loadDatabase();

setInterval(() => {
    const now = Date.now();
    // Limpar tokens expirados
    Object.keys(DB.sessionTokens).forEach(t => {
        if (DB.sessionTokens[t].expiresAt < now) delete DB.sessionTokens[t];
    });
    // Limpar rate limits antigos
    Object.keys(DB.ipRequests).forEach(ip => {
        DB.ipRequests[ip].requests = DB.ipRequests[ip].requests.filter(t => now - t < 60000);
    });
    saveDatabase();
}, 300000);

server.listen(PORT, '0.0.0.0', () => {
    console.log('═══════════════════════════════════════');
    console.log('🛡️ FLUXO - SEGURANÇA NÍVEL DEUS SUPREMO');
    console.log('📡 Porta:', PORT);
    console.log('🔒 10 CAMADAS DE PROTEÇÃO ATIVAS');
    console.log('  1. Blacklist Global');
    console.log('  2. IP Ban');
    console.log('  3. DDoS Protection');
    console.log('  4. Rate Limiting');
    console.log('  5. Header Validation');
    console.log('  6. Suspension Check');
    console.log('  7. Honeypot (Anti-Bot)');
    console.log('  8. SQL Injection Detection');
    console.log('  9. Content Sanitization (Anti-XSS)');
    console.log(' 10. Race Condition Detection');
    console.log('═══════════════════════════════════════');
});
