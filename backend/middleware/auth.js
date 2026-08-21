const jwt = require("jsonwebtoken");

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "goorkaz-dev-secret-change-this";


/**
 * Verifica que exista un token válido.
 */
function authenticateToken(req, res, next) {

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


/**
 * Permite únicamente determinados roles.
 *
 * Ejemplo:
 *
 * requireRole("admin")
 *
 * o:
 *
 * requireRole("admin", "operador")
 */
function requireRole(...roles) {

    return (req, res, next) => {

        if (!req.user) {

            return res.status(401).json({

                success: false,

                message:
                    "Usuario no autenticado"

            });

        }

        if (
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


module.exports = {

    authenticateToken,

    requireRole

};
