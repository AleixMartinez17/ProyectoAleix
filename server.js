require('dotenv').config();
require('dotenv').config();
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const { body, validationResult } = require("express-validator");
const { exec } = require('child_process');
const basicAuth = require('express-basic-auth');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const semver = require('semver');

const FAILED_LOGIN_ATTEMPTS_LIMIT = 5;
const LOGIN_BLOCK_TIME = 15 * 60 * 1000; // 15 minutos en milisegundos

const app = express();

// ================= CONFIGURACIÓN INICIAL ================= //
const allowedOrigins = [
  'http://localhost',
  'http://127.0.0.1', 
  'http://localhost:5500',
  'null'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`⚠️ Intento de acceso desde origen no permitido: ${origin}`);
      callback(new Error('Acceso bloqueado por política CORS'));
    }
  },
  methods: "GET,POST,PUT,DELETE,OPTIONS",
  allowedHeaders: ["Content-Type", "Authorization", "Origin", "X-Requested-With"],
  exposedHeaders: ["Authorization"],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204,
  maxAge: 86400
};

app.use(helmet());
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Expose-Headers', 'Authorization');
  res.header('X-Powered-By', 'Mi Super Servidor');
  next();
});

app.use(express.json());

<<<<<<< HEAD
/* ================= RATE LIMITING ================= 
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Demasiados intentos desde esta IP. Inténtalo más tarde.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: 15 * 60 // segundos
    });
  },
  skipSuccessfulRequests: true,
  keyGenerator: (req) => req.ip,
  standardHeaders: true,
  legacyHeaders: false
=======
// Configuración de la base de datos
const pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "pfg_aleix",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
>>>>>>> abe6bc4dc95d4d6a13489bd2c5d9ed51f6be62f4
});

/*/

// ================= BASE DE DATOS ================= //
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "pfg_aleix",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function initializeSecurityColumns() {
  try {
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS login_attempts INT NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS last_failed_login DATETIME NULL
    `);
    console.log('✅ Columnas de seguridad verificadas');
  } catch (error) {
    console.error('❌ Error verificando columnas:', error.message);
  }
}

initializeSecurityColumns();

const checkLoginAttempts = async (req, res, next) => {
  console.log('🔍 Ejecutando middleware de intentos...');
  const { email } = req.body;
  
  if (!email) return next();
  
  try {
    const conn = await pool.getConnection();
    try {
      const [users] = await conn.query(
        "SELECT id, login_attempts, last_failed_login FROM users WHERE email = ? FOR UPDATE", 
        [email]
      );
      
      if (users.length === 0) {
        console.log('📭 Usuario no encontrado, pasando al siguiente middleware');
        return next();
      }

      const user = users[0];
      const now = new Date();
      const lastAttempt = user.last_failed_login ? new Date(user.last_failed_login) : null;
      
      if (user.login_attempts >= FAILED_LOGIN_ATTEMPTS_LIMIT && lastAttempt) {
        const timeDiff = now - lastAttempt;
        if (timeDiff < LOGIN_BLOCK_TIME) {
          const remainingMinutes = Math.ceil((LOGIN_BLOCK_TIME - timeDiff) / (60 * 1000));
          console.log(`🚫 Cuenta bloqueada. Tiempo restante: ${remainingMinutes} minutos`);
          return res.status(429).json({
            success: false,
            message: `Cuenta bloqueada temporalmente. Inténtalo de nuevo en ${remainingMinutes} minutos y genere un nuevo QR para volver a iniciar sesion`,
            remainingTime: remainingMinutes
          });
        } else {
          await conn.query(
            "UPDATE users SET login_attempts = 0 WHERE id = ?",
            [user.id]
          );
          console.log('🔄 Bloqueo expirado, contador reiniciado');
        }
      }
      next();
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('⚠️ Error en checkLoginAttempts:', error);
    next();
  }
};

async function handleFailedLogin(email) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    
    const [users] = await conn.query(
      "SELECT id FROM users WHERE email = ? FOR UPDATE", 
      [email]
    );
    
    if (users.length === 0) {
      console.log('📭 Email no existe, no se incrementa contador');
      return;
    }
    
    const [result] = await conn.query(
      `UPDATE users 
       SET 
         login_attempts = IF(
           last_failed_login IS NULL OR 
           TIMESTAMPDIFF(MINUTE, last_failed_login, NOW()) >= ?,
           1,
           login_attempts + 1
         ),
         last_failed_login = NOW()
       WHERE id = ?`,
      [LOGIN_BLOCK_TIME / (60 * 1000), users[0].id]
    );
    
    await conn.commit();
    
    const [updatedUser] = await conn.query(
      "SELECT login_attempts FROM users WHERE id = ?",
      [users[0].id]
    );
    
    console.log(`❌ Intento fallido. Total intentos: ${updatedUser[0].login_attempts}`);
    
    if (updatedUser[0].login_attempts >= FAILED_LOGIN_ATTEMPTS_LIMIT) {
      console.warn(`🚨 ¡Usuario ${email} ha sido bloqueado temporalmente!`);
    }
  } catch (error) {
    await conn.rollback();
    console.error('💥 Error en handleFailedLogin:', {
      message: error.message,
      sql: error.sql,
      code: error.code
    });
  } finally {
    conn.release();
  }
}


app.post("/register", 
  [
    // Validación del nombre
    body('name')
      .trim()
      .notEmpty().withMessage('El nombre es obligatorio')
      .isLength({ min: 2 }).withMessage('El nombre debe tener al menos 2 caracteres')
      .matches(/^[A-Za-záéíóúüñÁÉÍÓÚÜÑ\s]+$/).withMessage('El nombre solo puede contener letras y espacios'),
    
    // Validación del email
    body('email')
      .notEmpty().withMessage('El email es obligatorio')
      .isEmail().withMessage('Debe ser un email válido (ej: usuario@dominio.com)')
      .normalizeEmail(),
    
    // Validación de la contraseña
    body('password')
      .notEmpty().withMessage('La contraseña es obligatoria')
      .isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres')
      .matches(/[A-Z]/).withMessage('Debe contener al menos una mayúscula (A-Z)')
      .matches(/[a-z]/).withMessage('Debe contener al menos una minúscula (a-z)')
      .matches(/[0-9]/).withMessage('Debe contener al menos un número (0-9)')
      .matches(/[\W_]/).withMessage('Debe contener al menos un símbolo (!, @, #, etc.)')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: "Errores de validación",
        errors: errors.array(),
        code: "VALIDATION_ERROR"
      });
    }

    let conn;
    try {
      const { name, email, password } = req.body;
      conn = await pool.getConnection();
      
      // Iniciar transacción
      await conn.beginTransaction();

      // 1. Verificar si el email existe (con LOCK para evitar condiciones de carrera)
      const [existing] = await conn.query(
        "SELECT id FROM users WHERE email = ? FOR UPDATE",
        [email]
      );

      if (existing.length > 0) {
        await conn.rollback();
        return res.status(409).json({
          success: false,
          message: "El email ya está registrado",
          code: "EMAIL_ALREADY_EXISTS"
        });
      }

      // 2. Hash de la contraseña y generación de MFA
      const hashedPassword = await bcrypt.hash(password, 10);
      const secret = speakeasy.generateSecret({ 
        length: 20,
        name: `MiApp (${email})`,
        issuer: "MiApp"
      });

      const backupCodes = Array.from({length: 5}, () => 
        Math.floor(100000 + Math.random() * 900000).toString()
      );

      // 3. Inserción en la base de datos
      const [result] = await conn.query(
        "INSERT INTO users (name, email, password, mfa_secret, backup_codes) VALUES (?, ?, ?, ?, ?)",
        [name, email, hashedPassword, secret.base32, JSON.stringify(backupCodes)]
      );

      // 4. Generación del QR Code
      const qrCodeDataURL = await qrcode.toDataURL(secret.otpauth_url);

      // Confirmar transacción
      await conn.commit();

      // Respuesta exitosa
      res.status(201).json({
        success: true,
        qrCodeDataURL,
        backupCodes,
        user: {
          id: result.insertId,
          name,
          email
        }
      });

    } catch (error) {
      // Rollback en caso de error
      if (conn) await conn.rollback();
      
      console.error("Error en registro:", {
        message: error.message,
        code: error.code,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });

      let statusCode = 500;
      let errorMessage = "Error en el servidor";
      let errorCode = "INTERNAL_ERROR";

      if (error.code === 'ER_DUP_ENTRY') {
        statusCode = 409;
        errorMessage = "El email ya está registrado";
        errorCode = "DUPLICATE_EMAIL";
      }

      res.status(statusCode).json({
        success: false,
        message: errorMessage,
        code: errorCode,
        ...(process.env.NODE_ENV === 'development' && { detail: error.message })
      });
    } finally {
      if (conn) conn.release();
    }
  }
);

app.post("/login-precheck", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email y contraseña son requeridos"
            });
        }

        const [users] = await pool.query(
            "SELECT id, name, password FROM users WHERE email = ?",
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Credenciales inválidas"
            });
        }

        const passwordMatch = await bcrypt.compare(password, users[0].password);
        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Credenciales inválidas"
            });
        }

        res.json({
            success: true,
            message: "Procede con MFA",
            user: {
                id: users[0].id,
                name: users[0].name
            }
        });

    } catch (error) {
        console.error("Error en login-precheck:", error);
        res.status(500).json({
            success: false,
            message: "Error en el servidor"
        });
    }
});

app.post("/login", 
  // Middleware para verificar Content-Type
  (req, res, next) => {
    if (!req.is('application/json')) {
      return res.status(415).json({
        success: false,
        message: "El encabezado Content-Type debe ser 'application/json'",
        receivedContentType: req.get('Content-Type')
      });
    }
    next();
  },

  // Middleware para validar campos requeridos
  (req, res, next) => {
    const { email, password, token } = req.body;
    const missingFields = [];
    
    if (!email || typeof email !== 'string') missingFields.push('email(string)');
    if (!password || typeof password !== 'string') missingFields.push('password(string)');
    if (!token || typeof token !== 'string') missingFields.push('token(string)');
    
    if (missingFields.length > 0) {
      console.error('⚠️ Campos faltantes o inválidos:', {
        missingFields,
        received: Object.keys(req.body).map(k => `${k}(${typeof req.body[k]})`)
      });
      return res.status(400).json({
        success: false,
        message: "Todos los campos son obligatorios y deben ser strings",
        required: ["email(string)", "password(string)", "token(string)"],
        received: Object.keys(req.body).map(k => `${k}(${typeof req.body[k]})`)
      });
    }
    next();
  },

  // Rate limiting
  //loginLimiter,

  // Control de intentos fallidos
  checkLoginAttempts,

  // Handler principal
  async (req, res) => {
    const { email, password, token: mfaToken } = req.body;
    let conn;

    try {
      conn = await pool.getConnection();
      
      // 1. Buscar usuario
      const [users] = await conn.query(
        `SELECT id, email, password, name, mfa_secret, backup_codes, login_attempts 
         FROM users WHERE email = ? FOR UPDATE`,
        [email]
      );

      if (users.length === 0) {
        console.warn(`📭 Usuario no encontrado: ${email}`);
        await handleFailedLogin(email);
        return res.status(401).json({
          success: false,
          message: "Credenciales inválidas"
        });
      }

      const user = users[0];
      
      // 2. Verificar contraseña
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        console.warn(`❌ Contraseña incorrecta para: ${email}`);
        await handleFailedLogin(email);
        return res.status(401).json({
          success: false,
          message: "Credenciales inválidas",
          attemptsLeft: FAILED_LOGIN_ATTEMPTS_LIMIT - user.login_attempts - 1
        });
      }

      // 3. Verificar MFA
      const backupCodes = JSON.parse(user.backup_codes || "[]");
      const tokenValid = speakeasy.totp.verify({
        secret: user.mfa_secret,
        encoding: "base32",
        token: mfaToken,
        window: 2
      });

      const isBackupCode = backupCodes.includes(mfaToken);

      if (!tokenValid && !isBackupCode) {
        console.warn(`🛡️ Código MFA inválido para: ${email}`);
        await handleFailedLogin(email);
        return res.status(401).json({
          success: false,
          message: "Código MFA inválido",
          attemptsLeft: FAILED_LOGIN_ATTEMPTS_LIMIT - user.login_attempts - 1
        });
      }

      // 4. Login exitoso - resetear intentos
      await conn.query(
        "UPDATE users SET login_attempts = 0, last_failed_login = NULL WHERE id = ?",
        [user.id]
      );

      // 5. Generar token JWT
      const token = jwt.sign(
        { 
          userId: user.id, 
          email: user.email,
          authLevel: "full"
        },
        process.env.JWT_SECRET || 'tu_secreto_seguro',
        { expiresIn: '1h' }
      );

      // 6. Si usó código de respaldo, actualizar la lista
      if (isBackupCode) {
        const newBackupCodes = backupCodes.filter(code => code !== mfaToken);
        await conn.query(
          "UPDATE users SET backup_codes = ? WHERE id = ?",
          [JSON.stringify(newBackupCodes), user.id]
        );
        console.warn(`⚠️ Usó código de respaldo para: ${email}. Códigos restantes: ${newBackupCodes.length}`);
      }

      console.log(`✅ Login exitoso para: ${email}`);
      
      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          mfaRequired: true
        },
        backupCodesRemaining: isBackupCode ? newBackupCodes.length : undefined
      });

    } catch (error) {
      console.error('💥 Error durante el login:', {
        error: error.message,
        stack: error.stack,
        email,
        timestamp: new Date().toISOString()
      });
      
      res.status(500).json({
        success: false,
        message: process.env.NODE_ENV === 'development' 
          ? `Error: ${error.message}`
          : "Error interno del servidor",
        referenceId: Date.now() // ID para rastrear el error en logs
      });
    } finally {
      if (conn) conn.release();
    }
  }
);

app.get("/generate-new-qr", async (req, res) => {
    try {
        const { email } = req.query;
        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email es requerido"
            });
        }

        const newSecret = speakeasy.generateSecret({ 
            length: 20,
            name: `MiApp (${email})`,
            issuer: "MiApp"
        });

        await pool.query(
            "UPDATE users SET mfa_secret = ? WHERE email = ?",
            [newSecret.base32, email]
        );

        const qrCodeDataURL = await qrcode.toDataURL(newSecret.otpauth_url);

        res.json({
            success: true,
            qrCodeDataURL
        });

    } catch (error) {
        console.error("Error generando QR:", error);
        res.status(500).json({
            success: false,
            message: "Error generando nuevo QR"
        });
    }
});

app.get('/cors-test', (req, res) => {
  res.json({ 
    status: 'success',
    message: '¡CORS configurado correctamente!',
    allowedOrigins: allowedOrigins,
    yourOrigin: req.headers.origin || 'No detectado',
    timestamp: new Date().toISOString()
  });
});

app.use((err, req, res, next) => {
  if (err.message === 'Acceso bloqueado por política CORS') {
    return res.status(403).json({
      success: false,
      message: "Acceso no autorizado desde tu dominio",
      code: "CORS_POLICY"
    });
  }

  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: "Error interno del servidor",
    code: "INTERNAL_SERVER_ERROR"
  });
});

const auditAuth = basicAuth({
  users: { 
    [process.env.AUDIT_USER || 'admin']: process.env.AUDIT_PASSWORD || 'AdminSeguro123!' 
  },
  challenge: true,
  unauthorizedResponse: {
    success: false,
    message: "Acceso no autorizado al escáner de dependencias"
  }
});

app.get('/api/security/scan-dependencies', auditAuth, async (req, res) => {
    const projectPath = path.resolve('C:/users/aleix/Desktop/PROYECTO');
    req.startTime = Date.now();
    
    try {
        // Leer package.json y package-lock.json
        const packageJson = JSON.parse(fs.readFileSync(path.join(projectPath, 'package.json')));
        const packageLockJson = fs.existsSync(path.join(projectPath, 'package-lock.json')) ? 
            JSON.parse(fs.readFileSync(path.join(projectPath, 'package-lock.json'))) : null;

        // Función mejorada para ejecutar comandos
        const executeCmd = async (cmd, critical = false) => {
            return new Promise((resolve) => {
                exec(cmd, {
                    cwd: projectPath,
                    shell: 'powershell.exe',
                    timeout: 120000,
                    maxBuffer: 1024 * 1024 * 20
                }, (error, stdout, stderr) => {
                    if (error && critical) {
                        console.error(`Error ejecutando comando crítico: ${cmd}`, error);
                        throw new Error(`Comando crítico falló: ${cmd}`);
                    }
                    resolve({
                        success: !error,
                        output: stdout.toString().trim(),
                        error: error ? stderr.toString() : null,
                        command: cmd
                    });
                });
            });
        };

        // Ejecutar comandos en paralelo
        const [npmInstallResult, auditResult, listResult, outdatedResult, checkUpdatesResult] = await Promise.allSettled([
            executeCmd('npm install --package-lock-only --no-audit', true),
            executeCmd('npm audit --json --audit-level=critical'),
            executeCmd('npm list --prod --json --depth=2'),
            executeCmd('npm outdated --json'),
            executeCmd('npx npm-check-updates --json')
        ]);

        // Función mejorada para parsear la salida
        const parseOutput = (output) => {
            try {
                if (!output || typeof output !== 'string') return null;
                
                // Intenta parsear directamente
                try {
                    return JSON.parse(output);
                } catch (e) {
                    // Si falla, busca el JSON dentro del output
                    const jsonStart = output.indexOf('{');
                    const jsonEnd = output.lastIndexOf('}') + 1;
                    if (jsonStart === -1 || jsonEnd === 0) return null;
                    const jsonStr = output.slice(jsonStart, jsonEnd);
                    return JSON.parse(jsonStr);
                }
            } catch (e) {
                console.error('Error parseando JSON:', e);
                return null;
            }
        };

        // Procesar resultados con mejor manejo de errores
        const auditData = auditResult.status === 'fulfilled' ? parseOutput(auditResult.value.output) || {} : {};
        const listData = listResult.status === 'fulfilled' ? parseOutput(listResult.value.output) || {} : {};
        const outdatedData = outdatedResult.status === 'fulfilled' ? parseOutput(outdatedResult.value.output) || {} : {};
        const updatesData = checkUpdatesResult.status === 'fulfilled' ? parseOutput(checkUpdatesResult.value.output) || {} : {};
        const directDependencies = Object.keys(packageJson.dependencies || {});
        const devDependencies = Object.keys(packageJson.devDependencies || {});

        // Función mejorada para obtener vulnerabilidades
        const getPackageVulnerabilities = (pkgName) => {
            if (!auditData.vulnerabilities || typeof auditData.vulnerabilities !== 'object') {
                return [];
            }
            
            const vulnerabilities = [];
            
            // Buscar vulnerabilidades directas
            if (auditData.vulnerabilities[pkgName]) {
                const vuln = auditData.vulnerabilities[pkgName];
                vulnerabilities.push({
                    severity: vuln.severity || 'unknown',
                    title: vuln.title || `Vulnerabilidad en ${pkgName}`,
                    patchedIn: vuln.fixAvailable ? 
                        (typeof vuln.fixAvailable === 'string' ? vuln.fixAvailable : 
                         vuln.fixAvailable.name ? vuln.fixAvailable.name.split('@')[1] : 
                         'Actualizar a última versión') : 
                        'No disponible',
                    id: vuln.id || 'unknown',
                    url: vuln.url || `https://npmjs.com/advisories/${vuln.id || 'unknown'}`,
                    via: vuln.via || []
                });
            }
            
            // Buscar en metadatos si existe
            if (auditData.metadata?.vulnerabilities) {
                Object.entries(auditData.metadata.vulnerabilities).forEach(([severity, count]) => {
                    if (count > 0) {
                        vulnerabilities.push({
                            severity,
                            title: `${count} vulnerabilidad(es) ${severity} en ${pkgName}`,
                            patchedIn: 'Ver detalles',
                            id: 'multiple',
                            url: `https://npmjs.com/package/${pkgName}`
                        });
                    }
                });
            }
            
            return vulnerabilities.length > 0 ? vulnerabilities : [];
        };

        // Función mejorada para analizar el árbol de dependencias
        const analyzeDependencyTree = (deps, directDependencies, level = 0, parent = null) => {
            if (!deps || typeof deps !== 'object') {
                if (level > 0) { // Solo mostrar advertencia para niveles profundos
                    console.warn(`Dependencias no definidas o inválidas en nivel ${level} para ${parent}`);
                }
                return [];
            }
            
            try {
                // Manejar diferentes formatos de npm list
                const dependencies = deps.dependencies || deps;
                
                return Object.entries(dependencies)
                    .filter(([name]) => name && typeof name === 'string')
                    .map(([name, data]) => {
                        if (!data || typeof data !== 'object') {
                            console.warn(`Datos de dependencia inválidos para ${name}`);
                            return null;
                        }
                        
                        const version = data.version || 'desconocida';
                        const isOutdated = outdatedData && outdatedData[name];
                        
                        let latestVersion = 'desconocida';
                        if (updatesData && updatesData[name]) {
                            latestVersion = updatesData[name];
                        } else if (isOutdated && isOutdated.latest) {
                            latestVersion = isOutdated.latest;
                        }
                        
                        const vulnerabilities = getPackageVulnerabilities(name);
                        const isDirectDependency = directDependencies.includes(name);
                        
                        const dependencyInfo = {
                            name,
                            version,
                            latestVersion,
                            isOutdated: !!isOutdated,
                            vulnerabilities,
                            hasVulnerabilities: vulnerabilities.length > 0,
                            isDirectDependency,
                            level,
                            parent,
                            deprecated: data.deprecated || false,
                            resolved: data.resolved || 'desconocido',
                            overridden: data.overridden || false,
                            dependencies: analyzeDependencyTree(
                                data.dependencies || {}, 
                                directDependencies, 
                                level + 1, 
                                name
                            )
                        };

                        if (vulnerabilities.length > 0) {
                            const severities = vulnerabilities.map(v => v.severity || 'unknown');
                            if (severities.includes('critical')) dependencyInfo.maxSeverity = 'critical';
                            else if (severities.includes('high')) dependencyInfo.maxSeverity = 'high';
                            else if (severities.includes('moderate')) dependencyInfo.maxSeverity = 'moderate';
                            else if (severities.includes('low')) dependencyInfo.maxSeverity = 'low';
                        }

                        return dependencyInfo;
                    })
                    .filter(Boolean);
            } catch (error) {
                console.error(`Error analizando árbol de dependencias (nivel ${level}):`, error);
                return [];
            }
        };

        const analyzedDependencies = analyzeDependencyTree(
            listData || {}, 
            directDependencies
        );

        // Función mejorada para generar resumen de vulnerabilidades
        const getVulnerabilitiesSummary = () => {
            const vulnerabilities = [];
            
            if (auditData.vulnerabilities) {
                Object.entries(auditData.vulnerabilities).forEach(([pkgName, vuln]) => {
                    // Mejorar la obtención de información de vulnerabilidades
                    const viaInfo = Array.isArray(vuln.via) ? 
                        vuln.via.find(item => typeof item === 'object') : null;
                    
                    const title = viaInfo?.title || vuln.title || `Vulnerabilidad en ${pkgName}`;
                    const url = viaInfo?.url || vuln.url || 
                        (vuln.id ? `https://npmjs.com/advisories/${vuln.id}` : 
                         `https://npmjs.com/package/${pkgName}`);
                    
                    vulnerabilities.push({
                        severity: vuln.severity || 'unknown',
                        title: title,
                        package: pkgName,
                        versionRange: vuln.range || 'versión-desconocida',
                        patchedIn: vuln.fixAvailable ? 
                            (typeof vuln.fixAvailable === 'string' ? vuln.fixAvailable : 
                             vuln.fixAvailable.name ? vuln.fixAvailable.name.split('@')[1] : 
                             'Actualizar a última versión') : 
                            'No disponible',
                        path: vuln.nodes?.[0]?.path || 'Directa',
                        url: url,
                        recommendation: vuln.fixAvailable ? 
                            `Actualizar a ${typeof vuln.fixAvailable === 'string' ? vuln.fixAvailable : 
                              vuln.fixAvailable.name ? vuln.fixAvailable.name.split('@')[1] : 
                              'última versión'}` : 
                            'Sin solución disponible',
                        via: vuln.via || []
                    });
                });
            }
            
            // Agregar resumen de metadatos si no hay vulnerabilidades específicas
            if (vulnerabilities.length === 0 && auditData.metadata?.vulnerabilities) {
                Object.entries(auditData.metadata.vulnerabilities).forEach(([severity, count]) => {
                    if (count > 0) {
                        vulnerabilities.push({
                            severity,
                            title: `${count} vulnerabilidad(es) ${severity}`,
                            package: 'Varios paquetes',
                            versionRange: 'Múltiples versiones',
                            patchedIn: 'Ver detalles completos',
                            path: 'Múltiples',
                            url: 'https://npmjs.com/advisories',
                            recommendation: 'Ejecutar "npm audit fix"'
                        });
                    }
                });
            }
            
            return vulnerabilities;
        };

        // Función mejorada para generar recomendaciones
        const generateRecommendations = () => {
            const recommendations = [];
            
            // Resumen de vulnerabilidades
            const vulnSummary = auditData.metadata?.vulnerabilities || {};
            if (vulnSummary.critical > 0) {
                recommendations.push({
                    priority: 'CRÍTICA',
                    action: `Actualizar ${vulnSummary.critical} paquete(s) con vulnerabilidades CRÍTICAS`,
                    commands: ['npm audit fix --force'],
                    details: 'Estas vulnerabilidades representan el mayor riesgo para tu aplicación'
                });
            }
            
            if (vulnSummary.high > 0) {
                recommendations.push({
                    priority: 'ALTA',
                    action: `Actualizar ${vulnSummary.high} paquete(s) con vulnerabilidades ALTAS`,
                    commands: ['npm audit fix'],
                    details: 'Estas vulnerabilidades representan un riesgo significativo'
                });
            }
            
            // Dependencias desactualizadas
            const outdatedCount = Object.keys(outdatedData).length;
            if (outdatedCount > 0) {
                recommendations.push({
                    priority: outdatedCount > 5 ? 'ALTA' : 'MEDIA',
                    action: `Actualizar ${outdatedCount} paquete(s) desactualizado(s)`,
                    commands: [
                        'npm update',
                        'npx npm-check-updates -u && npm install'
                    ],
                    details: 'Las versiones desactualizadas pueden contener vulnerabilidades conocidas'
                });
            }
            
            // Recomendaciones específicas para vulnerabilidades conocidas
            if (auditData.vulnerabilities) {
                Object.entries(auditData.vulnerabilities).forEach(([pkgName, vuln]) => {
                    if (vuln.severity === 'critical' || vuln.severity === 'high') {
                        // Mejorar la obtención de información de vulnerabilidades
                        const viaInfo = Array.isArray(vuln.via) ? 
                            vuln.via.find(item => typeof item === 'object') : null;
                        
                        const title = viaInfo?.title || vuln.title || `Vulnerabilidad en ${pkgName}`;
                        const url = viaInfo?.url || vuln.url || 
                            (vuln.id ? `https://npmjs.com/advisories/${vuln.id}` : 
                             `https://npmjs.com/package/${pkgName}`);
                        
                        let solution = 'Sin solución disponible';
                        let command = null;
                        
                        if (vuln.fixAvailable) {
                            if (typeof vuln.fixAvailable === 'string') {
                                solution = `Actualizar a ${vuln.fixAvailable}`;
                                command = `npm install ${pkgName}@${vuln.fixAvailable}`;
                            } else if (vuln.fixAvailable.name) {
                                solution = `Actualizar a ${vuln.fixAvailable.name}`;
                                command = `npm install ${vuln.fixAvailable.name}`;
                            } else if (vuln.fixAvailable === true) {
                                solution = 'Actualizar a última versión';
                                command = `npm install ${pkgName}@latest`;
                            }
                        }
                        
                        recommendations.push({
                            priority: vuln.severity.toUpperCase(),
                            package: pkgName,
                            action: `Vulnerabilidad ${vuln.severity}: ${title}`,
                            solution,
                            command,
                            url: url
                        });
                    }
                });
            }
            
            if (recommendations.length === 0) {
                recommendations.push({
                    priority: 'NINGUNA',
                    action: '¡Todas las dependencias están actualizadas y seguras!',
                    details: 'No se encontraron vulnerabilidades conocidas ni paquetes desactualizados'
                });
            }
            
            return recommendations.sort((a, b) => {
                const priorityOrder = { 'CRÍTICA': 1, 'ALTA': 2, 'MEDIA': 3, 'BAJA': 4, 'NINGUNA': 5 };
                return priorityOrder[a.priority] - priorityOrder[b.priority];
            });
        };

        // Funciones auxiliares
        const countTotalDependencies = (deps, count = 0) => {
            if (!deps) return count;
            for (const key in deps) {
                count++;
                if (deps[key].dependencies) {
                    count = countTotalDependencies(deps[key].dependencies, count);
                }
            }
            return count;
        };

        const countVulnerablePackages = () => {
            if (!auditData.vulnerabilities) return 0;
            return Object.keys(auditData.vulnerabilities).length;
        };

        const calculateRiskLevel = () => {
            const vulns = auditData.metadata?.vulnerabilities || {};
            if (vulns.critical > 0) return 'CRÍTICO 🔴';
            if (vulns.high > 0) return 'ALTO 🟠';
            if (vulns.moderate > 0) return 'MODERADO 🟡';
            if (vulns.low > 0) return 'BAJO 🟢';
            return 'NINGUNO ✅';
        };

        const calculateOutdatedRiskLevel = () => {
            const count = Object.keys(outdatedData).length;
            if (count > 10) return 'ALTO 🟠';
            if (count > 5) return 'MODERADO 🟡';
            if (count > 0) return 'BAJO 🟢';
            return 'ACTUALIZADO ✅';
        };

        // Generar informe completo
        const fullReport = {
            success: true,
            metadata: {
                project: packageJson.name || 'Sin nombre',
                version: packageJson.version || '0.0.0',
                timestamp: new Date().toISOString(),
                nodeVersion: process.version,
                scanDuration: `${((Date.now() - req.startTime) / 1000).toFixed(2)} segundos`
            },
            summary: {
                totalDependencies: countTotalDependencies(listData?.dependencies || {}),
                directDependencies: directDependencies.length,
                devDependencies: devDependencies.length,
                outdatedPackages: Object.keys(outdatedData).length,
                vulnerablePackages: countVulnerablePackages(),
                totalVulnerabilities: auditData.metadata?.vulnerabilities?.total || 0,
                securityRiskLevel: calculateRiskLevel(),
                outdatedRiskLevel: calculateOutdatedRiskLevel()
            },
            // Nueva sección de dependencias directas detalladas
            directDependencies: directDependencies.map(name => {
                const depData = analyzedDependencies.find(d => d.name === name) || {};
                const outdatedInfo = outdatedData[name] || {};
                const vulnerabilities = getPackageVulnerabilities(name);
                
                return {
                    name,
                    version: depData.version || packageJson.dependencies[name] || 'desconocida',
                    latestVersion: updatesData[name] || outdatedInfo.latest || 'desconocida',
                    isOutdated: !!outdatedInfo,
                    vulnerabilities: vulnerabilities,
                    hasVulnerabilities: vulnerabilities.length > 0,
                    deprecated: depData.deprecated || false,
                    requiredVersion: packageJson.dependencies[name] || 'desconocida'
                };
            }),
            dependencies: analyzedDependencies.filter(dep => dep.isDirectDependency),
            vulnerabilities: getVulnerabilitiesSummary(),
            outdatedDependencies: Object.entries(outdatedData).map(([name, data]) => ({
                name,
                current: data.current || 'desconocida',
                wanted: data.wanted || 'desconocida',
                latest: data.latest || 'desconocida',
                location: data.location || 'desconocido'
            })),
            recommendations: generateRecommendations(),
            rawData: req.query.raw === 'true' ? {
                package: packageJson,
                packageLock: packageLockJson,
                audit: auditData,
                list: listData,
                outdated: outdatedData,
                updates: updatesData
            } : undefined
        };

        // Función mejorada para formatear reporte para terminal
        const formatTerminalReport = (report) => {
            const colors = {
                reset: '\x1b[0m',
                bold: '\x1b[1m',
                red: '\x1b[31m',
                green: '\x1b[32m',
                yellow: '\x1b[33m',
                blue: '\x1b[34m',
                magenta: '\x1b[35m',
                cyan: '\x1b[36m',
                bgRed: '\x1b[41m',
                bgGreen: '\x1b[42m',
                bgYellow: '\x1b[43m'
            };

            const icons = {
                critical: '🔴',
                high: '🟠',
                moderate: '🟡',
                low: '🟢',
                check: '✅',
                warning: '⚠️',
                fire: '🔥',
                clock: '🕒',
                bulb: '💡',
                package: '📦',
                clipboard: '📋',
                chart: '📊',
                pin: '📌',
                direct: '⭐',
                dev: '🔧'
            };

            let output = '';

            // Encabezado
            output += `${colors.bold}${colors.cyan}${icons.package} INFORME DE SEGURIDAD DE DEPENDENCIAS ${icons.package}${colors.reset}\n`;
            output += `${colors.cyan}${'═'.repeat(60)}${colors.reset}\n\n`;
            
            // Metadatos
            output += `${colors.bold}${colors.blue}${icons.clipboard} METADATOS DEL PROYECTO${colors.reset}\n`;
            output += `  ${colors.bold}Nombre:${colors.reset} ${report.metadata.project}\n`;
            output += `  ${colors.bold}Versión:${colors.reset} ${report.metadata.version}\n`;
            output += `  ${colors.bold}Node.js:${colors.reset} ${report.metadata.nodeVersion}\n`;
            output += `  ${colors.bold}Tiempo análisis:${colors.reset} ${report.metadata.scanDuration}\n\n`;
            
            // Resumen
            output += `${colors.bold}${colors.blue}${icons.chart} RESUMEN DE DEPENDENCIAS${colors.reset}\n`;
            output += `  ${colors.bold}Total dependencias:${colors.reset} ${report.summary.totalDependencies}\n`;
            output += `  ${colors.bold}Dependencias directas:${colors.reset} ${report.summary.directDependencies}\n`;
            output += `  ${colors.bold}Dependencias de desarrollo:${colors.reset} ${report.summary.devDependencies}\n`;
            output += `  ${colors.bold}Paquetes desactualizados:${colors.reset} ${report.summary.outdatedPackages}\n`;
            output += `  ${colors.bold}Paquetes vulnerables:${colors.reset} ${report.summary.vulnerablePackages}\n`;
            output += `  ${colors.bold}Vulnerabilidades totales:${colors.reset} ${report.summary.totalVulnerabilities}\n`;
            
            // Nivel de riesgo con colores
            let riskColor = colors.green;
            if (report.summary.securityRiskLevel.includes('ALTO')) riskColor = colors.yellow;
            if (report.summary.securityRiskLevel.includes('CRÍTICO')) riskColor = colors.red;
            output += `  ${colors.bold}Nivel de riesgo seguridad:${colors.reset} ${riskColor}${report.summary.securityRiskLevel}${colors.reset}\n`;
            
            let outdatedRiskColor = colors.green;
            if (report.summary.outdatedRiskLevel.includes('MODERADO')) outdatedRiskColor = colors.yellow;
            if (report.summary.outdatedRiskLevel.includes('ALTO')) outdatedRiskColor = colors.red;
            output += `  ${colors.bold}Nivel de riesgo desactualización:${colors.reset} ${outdatedRiskColor}${report.summary.outdatedRiskLevel}${colors.reset}\n\n`;
            
            // Nueva sección: Dependencias directas
            output += `${colors.bold}${colors.blue}${icons.direct} DEPENDENCIAS DIRECTAS (${report.directDependencies.length}) ${icons.direct}${colors.reset}\n`;
            report.directDependencies.forEach(dep => {
                let depColor = colors.reset;
                let statusIcon = icons.check;
                
                if (dep.hasVulnerabilities) {
                    depColor = colors.red;
                    statusIcon = icons.warning;
                } else if (dep.isOutdated) {
                    depColor = colors.yellow;
                    statusIcon = icons.clock;
                } else if (dep.deprecated) {
                    depColor = colors.magenta;
                    statusIcon = icons.warning;
                }
                
                output += `  ${depColor}${statusIcon} ${dep.name}@${dep.version}${colors.reset}\n`;
                output += `    ${colors.bold}Requerida:${colors.reset} ${dep.requiredVersion}\n`;
                output += `    ${colors.bold}Última versión:${colors.reset} ${dep.latestVersion}\n`;
                
                if (dep.deprecated) {
                    output += `    ${colors.magenta}${icons.warning} DEPRECADA${colors.reset}\n`;
                }
                
                if (dep.vulnerabilities.length > 0) {
                    output += `    ${colors.red}${icons.warning} ${dep.vulnerabilities.length} vulnerabilidad(es)${colors.reset}\n`;
                    dep.vulnerabilities.forEach(vuln => {
                        output += `      ${colors.bold}${vuln.severity.toUpperCase()}:${colors.reset} ${vuln.title}\n`;
                        output += `      ${colors.bold}Solución:${colors.reset} ${vuln.patchedIn}\n`;
                        if (vuln.url) {
                            output += `      ${colors.blue}Más info: ${vuln.url}${colors.reset}\n`;
                        }
                    });
                }
                output += `\n`;
            });
            
            // Vulnerabilidades críticas/altas
            const criticalVulns = report.vulnerabilities.filter(v => v.severity === 'critical');
            const highVulns = report.vulnerabilities.filter(v => v.severity === 'high');
            
            if (criticalVulns.length > 0) {
                output += `${colors.bold}${colors.bgRed}${icons.fire} VULNERABILIDADES CRÍTICAS (${criticalVulns.length}) ${icons.fire}${colors.reset}\n`;
                criticalVulns.forEach(vuln => {
                    output += `  ${colors.red}${icons.warning} ${vuln.package}${colors.reset}\n`;
                    output += `    ${colors.bold}Título:${colors.reset} ${vuln.title}\n`;
                    output += `    ${colors.bold}Solución:${colors.reset} ${vuln.patchedIn}\n`;
                    output += `    ${colors.bold}Más info:${colors.reset} ${vuln.url}\n\n`;
                });
            }
            
            if (highVulns.length > 0) {
                output += `${colors.bold}${colors.magenta}${icons.warning} VULNERABILIDADES ALTAS (${highVulns.length}) ${icons.warning}${colors.reset}\n`;
                highVulns.forEach(vuln => {
                    output += `  ${colors.magenta}${icons.warning} ${vuln.package}${colors.reset}\n`;
                    output += `    ${colors.bold}Título:${colors.reset} ${vuln.title}\n`;
                    output += `    ${colors.bold}Solución:${colors.reset} ${vuln.patchedIn}\n`;
                    output += `    ${colors.bold}Más info:${colors.reset} ${vuln.url}\n\n`;
                });
            }
            
            // Recomendaciones
            output += `${colors.bold}${colors.cyan}${icons.bulb} RECOMENDACIONES ${icons.bulb}${colors.reset}\n`;
            report.recommendations.forEach((rec, i) => {
                let priorityColor = colors.green;
                if (rec.priority === 'ALTA') priorityColor = colors.magenta;
                if (rec.priority === 'CRÍTICA') priorityColor = colors.red;
                
                output += `  ${priorityColor}${i+1}. [${rec.priority}] ${rec.action}${colors.reset}\n`;
                if (rec.details) {
                    output += `    ${colors.yellow}${rec.details}${colors.reset}\n`;
                }
                if (rec.commands) {
                    rec.commands.forEach(cmd => {
                        output += `    ${colors.green}$ ${cmd}${colors.reset}\n`;
                    });
                }
                if (rec.url) {
                    output += `    ${colors.blue}Más información: ${rec.url}${colors.reset}\n`;
                }
                output += `\n`;
            });
            
            return output;
        };

        // Formatear respuesta según el cliente
        if (req.headers['user-agent']?.includes('curl')) {
            res.set('Content-Type', 'text/plain');
            return res.send(formatTerminalReport(fullReport));
        }

        res.json(fullReport);

    } catch (error) {
        console.error('💥 Error crítico:', error);
        res.status(500).json({
            success: false,
            message: "Fallo en el análisis de dependencias",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined,
            error: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// ================= MANEJO DE ERRORES ================= //
app.use((err, req, res, next) => {
  if (err.message === 'Acceso bloqueado por política CORS') {
    return res.status(403).json({
      success: false,
      message: "Acceso no autorizado desde tu dominio"
    });
  }

  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: "Error interno del servidor" 
});

const PORT = process.env.PORT || 3000;
<<<<<<< HEAD
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Servidor activo en http://localhost:${PORT}`);
  console.log("🔒 Endpoint de escaneo protegido en /api/security/scan-dependencies");
  console.log("🔑 Usa estas credenciales para acceder:");
  console.log(`   Usuario: ${process.env.AUDIT_USER || 'admin'}`);
  console.log(`   Contraseña: ${process.env.AUDIT_PASSWORD ? '••••••' : 'AdminSeguro123!'}`);
  console.log("\n🔧 Orígenes permitidos:");
  allowedOrigins.forEach(origin => console.log(`   → ${origin}`));
});
=======
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor activo en http://localhost:${PORT}`);
    console.log("🔧 Configuración CORS habilitada para:");
    allowedOrigins.forEach(origin => console.log(`   → ${origin}`));
});
>>>>>>> abe6bc4dc95d4d6a13489bd2c5d9ed51f6be62f4
