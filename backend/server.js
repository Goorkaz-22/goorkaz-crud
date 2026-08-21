const express = require("express");
const cors = require("cors");

const db = require("./database");

const authRoutes = require("./routes/auth");
const recordsRoutes = require("./routes/records");
const usersRoutes = require("./routes/users");

const app = express();

const PORT = process.env.PORT || 3000;


// =====================================================
// CONFIGURACIÓN
// =====================================================

app.use(
    cors()
);

app.use(
    express.json()
);


// =====================================================
// RUTA PRINCIPAL
// =====================================================

app.get(
    "/",
    (req, res) => {

        res.json({

            success: true,

            application:
                "Goorkaz CRUD",

            version:
                "3.0.0",

            status:
                "online"

        });

    }
);


// =====================================================
// HEALTH CHECK
// =====================================================

app.get(
    "/api/health",
    (req, res) => {

        res.json({

            success: true,

            message:
                "Goorkaz API funcionando correctamente",

            database:
                "SQLite",

            version:
                "3.0.0"

        });

    }
);


// =====================================================
// CREAR ADMINISTRADOR INICIAL
// =====================================================

const bcrypt = require("bcryptjs");


const adminExists =
    db.prepare(`
        SELECT id
        FROM users
        WHERE email = ?
    `).get(
        "admin@goorkaz.com"
    );


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
        "✓ Administrador inicial creado"
    );

}


// =====================================================
// RUTAS API
// =====================================================

app.use(
    "/api/auth",
    authRoutes
);


app.use(
    "/api/records",
    recordsRoutes
);


app.use(
    "/api/users",
    usersRoutes
);

const auditRoutes =
    require("./routes/audit");

app.use(
    "/api/audit",
    auditRoutes
);


// =====================================================
// RUTA 404
// =====================================================

app.use(
    (req, res) => {

        res.status(404).json({

            success: false,

            message:
                "Ruta no encontrada",

            path:
                req.originalUrl

        });

    }
);


// =====================================================
// MANEJO DE ERRORES
// =====================================================

app.use(
    (err, req, res, next) => {

        console.error(
            "ERROR:",
            err
        );


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
            "=========================================="
        );

        console.log(
            "        GOORKAZ CRUD V3"
        );

        console.log(
            "        BACKEND ONLINE"
        );

        console.log(
            "=========================================="
        );

        console.log(
            `Servidor: http://localhost:${PORT}`
        );

        console.log(
            `API:      http://localhost:${PORT}/api`
        );

        console.log(
            `Health:   http://localhost:${PORT}/api/health`
        );

        console.log(
            "=========================================="
        );

        console.log("");

        console.log(
            "Usuario inicial:"
        );

        console.log(
            "Email: admin@goorkaz.com"
        );

        console.log(
            "Password: Goorkaz123!"
        );

        console.log("");

    }
);
