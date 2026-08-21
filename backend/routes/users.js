const express = require("express");
const bcrypt = require("bcryptjs");

const db = require("../database");

const {
    authenticateToken,
    requireRole
} = require("../middleware/auth");

const router = express.Router();


// =====================================================
// ROLES PERMITIDOS
// =====================================================

const VALID_ROLES = [
    "admin",
    "operador",
    "consulta"
];


// =====================================================
// FUNCIÓN DE AUDITORÍA
// =====================================================

function createAudit(
    userId,
    action,
    description = ""
) {

    db.prepare(`
        INSERT INTO audit_logs
        (
            user_id,
            action,
            description
        )
        VALUES (?, ?, ?)
    `).run(
        userId,
        action,
        description
    );

}


// =====================================================
// LISTAR USUARIOS
// GET /api/users
// =====================================================

router.get(
    "/",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

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


        } catch (error) {

            console.error(
                "Error obteniendo usuarios:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudieron obtener los usuarios"

            });

        }

    }
);


// =====================================================
// OBTENER USUARIO
// GET /api/users/:id
// =====================================================

router.get(
    "/:id",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

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
                    req.params.id
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


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Error obteniendo el usuario"

            });

        }

    }
);


// =====================================================
// CREAR USUARIO
// POST /api/users
// =====================================================

router.post(
    "/",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

            const {
                name,
                email,
                password,
                role
            } = req.body;


            // -----------------------------------------
            // VALIDACIÓN DE CAMPOS
            // -----------------------------------------

            if (
                !name ||
                !email ||
                !password ||
                !role
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Nombre, correo, contraseña y rol son obligatorios"

                });

            }


            // -----------------------------------------
            // VALIDAR ROL
            // -----------------------------------------

            if (
                !VALID_ROLES.includes(role)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "El rol seleccionado no es válido"

                });

            }


            // -----------------------------------------
            // VALIDAR CONTRASEÑA
            // -----------------------------------------

            if (
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "La contraseña debe tener al menos 8 caracteres"

                });

            }


            // -----------------------------------------
            // NORMALIZAR CORREO
            // -----------------------------------------

            const normalizedEmail =
                email
                    .trim()
                    .toLowerCase();


            // -----------------------------------------
            // COMPROBAR CORREO
            // -----------------------------------------

            const existing =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE email = ?
                `).get(
                    normalizedEmail
                );


            if (existing) {

                return res.status(409).json({

                    success: false,

                    message:
                        "El correo ya está registrado"

                });

            }


            // -----------------------------------------
            // ENCRIPTAR CONTRASEÑA
            // -----------------------------------------

            const passwordHash =
                bcrypt.hashSync(
                    password,
                    12
                );


            // -----------------------------------------
            // CREAR USUARIO
            // -----------------------------------------

            const result =
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

                    name.trim(),

                    normalizedEmail,

                    passwordHash,

                    role,

                    1

                );


            // -----------------------------------------
            // OBTENER USUARIO CREADO
            // -----------------------------------------

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


            // -----------------------------------------
            // AUDITORÍA
            // -----------------------------------------

            createAudit(

                req.user.id,

                "CREATE_USER",

                `Creó al usuario ${user.name} (${user.email})`

            );


            res.status(201).json({

                success: true,

                message:
                    "Usuario creado correctamente",

                user

            });


        } catch (error) {

            console.error(
                "Error creando usuario:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo crear el usuario"

            });

        }

    }
);


// =====================================================
// CAMBIAR ROL
// PATCH /api/users/:id/role
// =====================================================

router.patch(
    "/:id/role",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

            const id =
                Number(req.params.id);

            const {
                role
            } = req.body;


            // -----------------------------------------
            // VALIDAR ROL
            // -----------------------------------------

            if (
                !VALID_ROLES.includes(role)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "El rol seleccionado no es válido"

                });

            }


            // -----------------------------------------
            // BUSCAR USUARIO
            // -----------------------------------------

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


            // -----------------------------------------
            // PROTECCIÓN DEL ADMIN ACTUAL
            // -----------------------------------------

            if (
                user.id === req.user.id &&
                role !== "admin"
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "No podés quitarte tu propio rol de administrador"

                });

            }


            // -----------------------------------------
            // ACTUALIZAR ROL
            // -----------------------------------------

            db.prepare(`
                UPDATE users
                SET role = ?
                WHERE id = ?
            `).run(
                role,
                id
            );


            // -----------------------------------------
            // AUDITORÍA
            // -----------------------------------------

            createAudit(

                req.user.id,

                "CHANGE_ROLE",

                `Cambió el rol de ${user.name} de ${user.role} a ${role}`

            );


            res.json({

                success: true,

                message:
                    "Rol actualizado correctamente"

            });


        } catch (error) {

            console.error(
                "Error cambiando rol:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo actualizar el rol"

            });

        }

    }
);


// =====================================================
// ACTIVAR / DESACTIVAR USUARIO
// PATCH /api/users/:id/status
// =====================================================

router.patch(
    "/:id/status",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

            const id =
                Number(req.params.id);


            // -----------------------------------------
            // BUSCAR USUARIO
            // -----------------------------------------

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


            // -----------------------------------------
            // IMPEDIR DESACTIVARSE A SÍ MISMO
            // -----------------------------------------

            if (
                user.id === req.user.id
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "No podés desactivar tu propia cuenta"

                });

            }


            // -----------------------------------------
            // NUEVO ESTADO
            // -----------------------------------------

            const newStatus =
                user.active ? 0 : 1;


            // -----------------------------------------
            // ACTUALIZAR
            // -----------------------------------------

            db.prepare(`
                UPDATE users
                SET active = ?
                WHERE id = ?
            `).run(
                newStatus,
                id
            );


            // -----------------------------------------
            // AUDITORÍA
            // -----------------------------------------

            createAudit(

                req.user.id,

                newStatus
                    ? "ACTIVATE_USER"
                    : "DEACTIVATE_USER",

                newStatus
                    ? `Activó al usuario ${user.name}`
                    : `Desactivó al usuario ${user.name}`

            );


            res.json({

                success: true,

                message:
                    newStatus
                        ? "Usuario activado correctamente"
                        : "Usuario desactivado correctamente",

                active:
                    newStatus

            });


        } catch (error) {

            console.error(
                "Error cambiando estado:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo cambiar el estado del usuario"

            });

        }

    }
);


// =====================================================
// CAMBIAR CONTRASEÑA
// PATCH /api/users/:id/password
// =====================================================

router.patch(
    "/:id/password",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

            const id =
                Number(req.params.id);

            const {
                password
            } = req.body;


            // -----------------------------------------
            // VALIDACIÓN
            // -----------------------------------------

            if (
                !password ||
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "La contraseña debe tener al menos 8 caracteres"

                });

            }


            // -----------------------------------------
            // BUSCAR USUARIO
            // -----------------------------------------

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


            // -----------------------------------------
            // HASH
            // -----------------------------------------

            const passwordHash =
                bcrypt.hashSync(
                    password,
                    12
                );


            // -----------------------------------------
            // ACTUALIZAR
            // -----------------------------------------

            db.prepare(`
                UPDATE users
                SET password = ?
                WHERE id = ?
            `).run(
                passwordHash,
                id
            );


            // -----------------------------------------
            // AUDITORÍA
            // -----------------------------------------

            createAudit(

                req.user.id,

                "CHANGE_PASSWORD",

                `Cambió la contraseña del usuario ${user.name}`

            );


            res.json({

                success: true,

                message:
                    "Contraseña actualizada correctamente"

            });


        } catch (error) {

            console.error(
                "Error cambiando contraseña:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo cambiar la contraseña"

            });

        }

    }
);


// =====================================================
// ELIMINAR USUARIO
// DELETE /api/users/:id
// =====================================================

router.delete(
    "/:id",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

            const id =
                Number(req.params.id);


            // -----------------------------------------
            // NO PERMITIR AUTOELIMINACIÓN
            // -----------------------------------------

            if (
                id === req.user.id
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "No podés eliminar tu propia cuenta"

                });

            }


            // -----------------------------------------
            // BUSCAR
            // -----------------------------------------

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


            // -----------------------------------------
            // PROTECCIÓN DEL ADMIN PRINCIPAL
            // -----------------------------------------

            if (
                user.email ===
                "admin@goorkaz.com"
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "El administrador principal no puede eliminarse"

                });

            }


            // -----------------------------------------
            // ELIMINAR
            // -----------------------------------------

            db.prepare(`
                DELETE FROM users
                WHERE id = ?
            `).run(id);


            // -----------------------------------------
            // AUDITORÍA
            // -----------------------------------------

            createAudit(

                req.user.id,

                "DELETE_USER",

                `Eliminó al usuario ${user.name} (${user.email})`

            );


            res.json({

                success: true,

                message:
                    "Usuario eliminado correctamente"

            });


        } catch (error) {

            console.error(
                "Error eliminando usuario:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo eliminar el usuario"

            });

        }

    }
);


module.exports = router;
