const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("../database");

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
            // BUSCAR USUARIO
            // -----------------------------------------

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE email = ?
                    AND active = 1
                `).get(

                    email
                        .trim()
                        .toLowerCase()

                );


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
// OBTENER USUARIO ACTUAL
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


// =====================================================
// MIDDLEWARE LOCAL
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


    } catch (error) {

        return res.status(401).json({

            success: false,

            message:
                "Token inválido o expirado"

        });

    }

}


module.exports = router;
