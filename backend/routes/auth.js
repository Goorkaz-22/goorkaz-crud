const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("../database");

const {
    authenticateToken
} = require("../middleware/auth");

const router = express.Router();

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


            if (!email || !password) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Correo y contraseña son obligatorios"
                });

            }


            const normalizedEmail =
                email
                    .trim()
                    .toLowerCase();


            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE email = ?
                    AND active = 1
                `).get(
                    normalizedEmail
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

        }

        catch (error) {

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


            if (!user) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Usuario no encontrado"

                });

            }


            if (!user.active) {

                return res.status(401).json({

                    success: false,

                    message:
                        "La cuenta está desactivada"

                });

            }


            res.json({

                success: true,

                user

            });

        }

        catch (error) {

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
