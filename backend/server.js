const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("./database");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
    process.env.JWT_SECRET || "goorkaz-dev-secret-change-this";


// =====================================================
// CONFIGURACIÓN
// =====================================================

app.use(cors());

app.use(express.json());


// =====================================================
// FUNCIONES AUXILIARES
// =====================================================

function createToken(user) {

    return jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "8h"
        }
    );

}


function createAudit(
    userId,
    action,
    recordId = null,
    description = ""
) {

    db.prepare(`
        INSERT INTO audit_logs
        (
            user_id,
            action,
            record_id,
            description
        )
        VALUES (?, ?, ?, ?)
    `).run(
        userId,
        action,
        recordId,
        description
    );

}


// =====================================================
// RUTA PRINCIPAL
// =====================================================

app.get("/", (req, res) => {

    res.json({
        success: true,
        application: "Goorkaz CRUD",
        version: "3.0.0",
        status: "online"
    });

});


// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/api/health", (req, res) => {

    res.json({
        success: true,
        message: "Goorkaz API funcionando correctamente"
    });

});


// =====================================================
// CREAR USUARIO ADMINISTRADOR INICIAL
// =====================================================

const adminExists = db.prepare(`
    SELECT id
    FROM users
    WHERE email = ?
`).get("admin@goorkaz.com");


if (!adminExists) {

    const passwordHash =
        bcrypt.hashSync(
            "Goorkaz123!",
            12
        );


    db.prepare(`
        INSERT INTO users
        (
            name,
            email,
            password,
            role,
            active
        )
        VALUES (?, ?, ?, ?, ?)
    `).run(
        "Administrador Goorkaz",
        "admin@goorkaz.com",
        passwordHash,
        "admin",
        1
    );


    console.log(
        "✓ Usuario administrador inicial creado"
    );

}


// =====================================================
// LOGIN
// =====================================================

app.post(
    "/api/auth/login",
    (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;


            if (!email || !password) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Correo y contraseña son obligatorios"

                });

            }


            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE email = ?
                    AND active = 1
                `).get(
                    email.trim().toLowerCase()
                );


            if (!user) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Credenciales incorrectas"

                });

            }


            const validPassword =
                bcrypt.compareSync(
                    password,
                    user.password
                );


            if (!validPassword) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Credenciales incorrectas"

                });

            }


            const token =
                createToken(user);


            res.json({

                success: true,

                message:
                    "Inicio de sesión correcto",

                token,

                user: {

                    id: user.id,

                    name: user.name,

                    email: user.email,

                    role: user.role

                }

            });


        } catch (error) {

            console.error(error);

            res.status(500).json({

                success: false,

                message:
                    "Error interno del servidor"

            });

        }

    }
);


// =====================================================
// MIDDLEWARE DE AUTENTICACIÓN
// =====================================================

function authenticateToken(
    req,
    res,
    next
) {

    const authHeader =
        req.headers.authorization;


    if (!authHeader) {

        return res.status(401).json({

            success: false,

            message:
                "Token no proporcionado"

        });

    }


    const parts =
        authHeader.split(" ");


    if (
        parts.length !== 2 ||
        parts[0] !== "Bearer"
    ) {

        return res.status(401).json({

            success: false,

            message:
                "Formato de token inválido"

        });

    }


    const token =
        parts[1];


    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );


        req.user = decoded;

        next();


    } catch {

        return res.status(401).json({

            success: false,

            message:
                "Token inválido o expirado"

        });

    }

}


// =====================================================
// MIDDLEWARE DE ROLES
// =====================================================

function requireRole(...roles) {

    return (req, res, next) => {

        if (
            !req.user ||
            !roles.includes(
                req.user.role
            )
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "No tenés permisos para realizar esta acción"

            });

        }


        next();

    };

}


// =====================================================
// PERFIL ACTUAL
// =====================================================

app.get(
    "/api/auth/me",
    authenticateToken,
    (req, res) => {

        const user =
            db.prepare(`
                SELECT
                    id,
                    name,
                    email,
                    role,
                    active,
                    created_at
                FROM users
                WHERE id = ?
            `).get(
                req.user.id
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "Usuario no encontrado"

            });

        }


        res.json({

            success: true,

            user

        });

    }
);


// =====================================================
// LISTAR REGISTROS
// =====================================================

app.get(
    "/api/records",
    authenticateToken,
    (req, res) => {

        const records =
            db.prepare(`
                SELECT *
                FROM records
                ORDER BY id DESC
            `).all();


        res.json({

            success: true,

            records

        });

    }
);


// =====================================================
// OBTENER UN REGISTRO
// =====================================================

app.get(
    "/api/records/:id",
    authenticateToken,
    (req, res) => {

        const record =
            db.prepare(`
                SELECT *
                FROM records
                WHERE id = ?
            `).get(
                req.params.id
            );


        if (!record) {

            return res.status(404).json({

                success: false,

                message:
                    "Registro no encontrado"

            });

        }


        res.json({

            success: true,

            record

        });

    }
);


// =====================================================
// CREAR REGISTRO
// =====================================================

app.post(
    "/api/records",
    authenticateToken,
    requireRole(
        "admin",
        "operador"
    ),
    (req, res) => {

        const {
            name,
            email,
            phone,
            category,
            status
        } = req.body;


        if (
            !name ||
            !email ||
            !category
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Nombre, correo y categoría son obligatorios"

            });

        }


        const result =
            db.prepare(`
                INSERT INTO records
                (
                    name,
                    email,
                    phone,
                    category,
                    status
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                name.trim(),
                email.trim(),
                phone || "",
                category,
                status || "Activo"
            );


        const record =
            db.prepare(`
                SELECT *
                FROM records
                WHERE id = ?
            `).get(
                result.lastInsertRowid
            );


        createAudit(
            req.user.id,
            "CREATE",
            record.id,
            `Creó el registro ${record.name}`
        );


        res.status(201).json({

            success: true,

            message:
                "Registro creado correctamente",

            record

        });

    }
);


// =====================================================
// EDITAR REGISTRO
// =====================================================

app.put(
    "/api/records/:id",
    authenticateToken,
    requireRole(
        "admin",
        "operador"
    ),
    (req, res) => {

        const id =
            req.params.id;


        const existing =
            db.prepare(`
                SELECT *
                FROM records
                WHERE id = ?
            `).get(id);


        if (!existing) {

            return res.status(404).json({

                success: false,

                message:
                    "Registro no encontrado"

            });

        }


        const {
            name,
            email,
            phone,
            category,
            status
        } = req.body;


        if (
            !name ||
            !email ||
            !category
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Nombre, correo y categoría son obligatorios"

            });

        }


        db.prepare(`
            UPDATE records
            SET
                name = ?,
                email = ?,
                phone = ?,
                category = ?,
                status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(
            name.trim(),
            email.trim(),
            phone || "",
            category,
            status || "Activo",
            id
        );


        const record =
            db.prepare(`
                SELECT *
                FROM records
                WHERE id = ?
            `).get(id);


        createAudit(
            req.user.id,
            "UPDATE",
            record.id,
            `Editó el registro ${record.name}`
        );


        res.json({

            success: true,

            message:
                "Registro actualizado correctamente",

            record

        });

    }
);


// =====================================================
// ELIMINAR REGISTRO
// =====================================================

app.delete(
    "/api/records/:id",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        const id =
            req.params.id;


        const record =
            db.prepare(`
                SELECT *
                FROM records
                WHERE id = ?
            `).get(id);


        if (!record) {

            return res.status(404).json({

                success: false,

                message:
                    "Registro no encontrado"

            });

        }


        db.prepare(`
            DELETE FROM records
            WHERE id = ?
        `).run(id);


        createAudit(
            req.user.id,
            "DELETE",
            id,
            `Eliminó el registro ${record.name}`
        );


        res.json({

            success: true,

            message:
                "Registro eliminado correctamente"

        });

    }
);


// =====================================================
// LISTAR USUARIOS
// =====================================================

app.get(
    "/api/users",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        const users =
            db.prepare(`
                SELECT
                    id,
                    name,
                    email,
                    role,
                    active,
                    created_at
                FROM users
                ORDER BY id DESC
            `).all();


        res.json({

            success: true,

            users

        });

    }
);


// =====================================================
// CREAR USUARIO
// =====================================================

app.post(
    "/api/users",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        const {
            name,
            email,
            password,
            role
        } = req.body;


        if (
            !name ||
            !email ||
            !password ||
            !role
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Todos los campos son obligatorios"

            });

        }


        const validRoles = [
            "admin",
            "operador",
            "consulta"
        ];


        if (
            !validRoles.includes(role)
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Rol inválido"

            });

        }


        const existing =
            db.prepare(`
                SELECT id
                FROM users
                WHERE email = ?
            `).get(
                email.trim().toLowerCase()
            );


        if (existing) {

            return res.status(409).json({

                success: false,

                message:
                    "El correo ya está registrado"

            });

        }


        const passwordHash =
            bcrypt.hashSync(
                password,
                12
            );


        const result =
            db.prepare(`
                INSERT INTO users
                (
                    name,
                    email,
                    password,
                    role
                )
                VALUES (?, ?, ?, ?)
            `).run(
                name.trim(),
                email.trim().toLowerCase(),
                passwordHash,
                role
            );


        const user =
            db.prepare(`
                SELECT
                    id,
                    name,
                    email,
                    role,
                    active,
                    created_at
                FROM users
                WHERE id = ?
            `).get(
                result.lastInsertRowid
            );


        res.status(201).json({

            success: true,

            message:
                "Usuario creado correctamente",

            user

        });

    }
);


// =====================================================
// ACTIVAR / DESACTIVAR USUARIO
// =====================================================

app.patch(
    "/api/users/:id/status",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        const id =
            req.params.id;


        const user =
            db.prepare(`
                SELECT *
                FROM users
                WHERE id = ?
            `).get(id);


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "Usuario no encontrado"

            });

        }


        const newStatus =
            user.active ? 0 : 1;


        db.prepare(`
            UPDATE users
            SET active = ?
            WHERE id = ?
        `).run(
            newStatus,
            id
        );


        res.json({

            success: true,

            message:
                newStatus
                    ? "Usuario activado"
                    : "Usuario desactivado"

        });

    }
);


// =====================================================
// AUDITORÍA
// =====================================================

app.get(
    "/api/audit",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        const logs =
            db.prepare(`
                SELECT
                    audit_logs.*,
                    users.name AS user_name,
                    users.email AS user_email
                FROM audit_logs
                LEFT JOIN users
                    ON users.id = audit_logs.user_id
                ORDER BY audit_logs.id DESC
                LIMIT 200
            `).all();


        res.json({

            success: true,

            logs

        });

    }
);


// =====================================================
// MANEJO DE ERRORES
// =====================================================

app.use(
    (err, req, res, next) => {

        console.error(err);

        res.status(500).json({

            success: false,

            message:
                "Error interno del servidor"

        });

    }
);


// =====================================================
// INICIAR SERVIDOR
// =====================================================

app.listen(
    PORT,
    () => {

        console.log("");
        console.log(
            "======================================"
        );
        console.log(
            "      GOORKAZ CRUD V3"
        );
        console.log(
            "      API ONLINE"
        );
        console.log(
            "======================================"
        );
        console.log(
            `Servidor: http://localhost:${PORT}`
        );
        console.log(
            `Health:   http://localhost:${PORT}/api/health`
        );
        console.log(
            "======================================"
        );
        console.log("");

    }
);
