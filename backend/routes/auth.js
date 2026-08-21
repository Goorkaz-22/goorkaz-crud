const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("../database");

const {
    authenticateToken
} = require("../middleware/auth");

const router = express.Router();


// =====================================================
// CONFIGURACIÓN JWT
// =====================================================

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "goorkaz-dev-secret-change-this";


// =====================================================
// GENERAR TOKEN
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


// =====================================================
// LOGIN
// POST /api/auth/login
// =====================================================

router.post(
    "/login",
    (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;


            // -----------------------------------------
            // VALIDACIÓN
            // -----------------------------------------

            if (
                !email ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Correo y contraseña son obligatorios"

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
            // BUSCAR USUARIO ACTIVO
            // -----------------------------------------

            const user =
                db.prepare(`
                    SELECT
                        id,
                        name,
                        email,
                        password,
                        role,
                        active
                    FROM users
                    WHERE email = ?
                    AND active = 1
                `).get(
                    normalizedEmail
                );


            // -----------------------------------------
            // USUARIO NO ENCONTRADO
            // -----------------------------------------

            if (!user) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Credenciales incorrectas"

                });

            }


            // -----------------------------------------
            // COMPROBAR CONTRASEÑA
            // -----------------------------------------

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


            // -----------------------------------------
            // CREAR TOKEN
            // -----------------------------------------

            const token =
                createToken(user);


            // -----------------------------------------
            // RESPUESTA
            // -----------------------------------------

            res.json({

                success: true,

                message:
                    "Inicio de sesión correcto",

                token,

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    email:
                        user.email,

                    role:
                        user.role

                }

            });


        } catch (error) {

            console.error(
                "Error en login:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Error interno del servidor"

            });

        }

    }
);


// =====================================================
// USUARIO ACTUAL
// GET /api/auth/me
// =====================================================

router.get(
    "/me",
    authenticateToken,
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
                    req.user.id
                );


            // -----------------------------------------
            // USUARIO NO EXISTE
            // -----------------------------------------

            if (!user) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Usuario no encontrado"

                });

            }


            // -----------------------------------------
            // USUARIO DESACTIVADO
            // -----------------------------------------

            if (!user.active) {

                return res.status(403).json({

                    success: false,

                    message:
                        "La cuenta está desactivada"

                });

            }


            // -----------------------------------------
            // RESPUESTA
            // -----------------------------------------

            res.json({

                success: true,

                user

            });


        } catch (error) {

            console.error(
                "Error obteniendo usuario:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Error interno del servidor"

            });

        }

    }
);


module.exports = router;
