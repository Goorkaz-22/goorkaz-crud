const express = require("express");

const db = require("../database");

const {
    authenticateToken,
    requireRole
} = require("../middleware/auth");

const router = express.Router();


// =====================================================
// FUNCIÓN DE AUDITORÍA
// =====================================================

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
// LISTAR REGISTROS
// GET /api/records
// =====================================================

router.get(
    "/",
    authenticateToken,
    (req, res) => {

        try {

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


        } catch (error) {

            console.error(
                "Error obteniendo registros:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudieron obtener los registros"

            });

        }

    }
);


// =====================================================
// OBTENER REGISTRO
// GET /api/records/:id
// =====================================================

router.get(
    "/:id",
    authenticateToken,
    (req, res) => {

        try {

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


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Error obteniendo el registro"

            });

        }

    }
);


// =====================================================
// CREAR REGISTRO
// POST /api/records
// =====================================================

router.post(
    "/",
    authenticateToken,
    requireRole(
        "admin",
        "operador"
    ),
    (req, res) => {

        try {

            const {
                name,
                email,
                phone,
                category,
                status
            } = req.body;


            // -----------------------------------------
            // VALIDACIONES
            // -----------------------------------------

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


            // -----------------------------------------
            // INSERTAR
            // -----------------------------------------

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


            // -----------------------------------------
            // OBTENER REGISTRO
            // -----------------------------------------

            const record =
                db.prepare(`
                    SELECT *
                    FROM records
                    WHERE id = ?
                `).get(
                    result.lastInsertRowid
                );


            // -----------------------------------------
            // AUDITORÍA
            // -----------------------------------------

            createAudit(

                req.user.id,

                "CREATE",

                record.id,

                `Creó el registro ${record.name}`

            );


            // -----------------------------------------
            // RESPUESTA
            // -----------------------------------------

            res.status(201).json({

                success: true,

                message:
                    "Registro creado correctamente",

                record

            });


        } catch (error) {

            console.error(
                "Error creando registro:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo crear el registro"

            });

        }

    }
);


// =====================================================
// EDITAR REGISTRO
// PUT /api/records/:id
// =====================================================

router.put(
    "/:id",
    authenticateToken,
    requireRole(
        "admin",
        "operador"
    ),
    (req, res) => {

        try {

            const id =
                req.params.id;


            // -----------------------------------------
            // COMPROBAR EXISTENCIA
            // -----------------------------------------

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


            // -----------------------------------------
            // VALIDACIONES
            // -----------------------------------------

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


            // -----------------------------------------
            // ACTUALIZAR
            // -----------------------------------------

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


            // -----------------------------------------
            // OBTENER ACTUALIZADO
            // -----------------------------------------

            const record =
                db.prepare(`
                    SELECT *
                    FROM records
                    WHERE id = ?
                `).get(id);


            // -----------------------------------------
            // AUDITORÍA
            // -----------------------------------------

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


        } catch (error) {

            console.error(
                "Error actualizando registro:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo actualizar el registro"

            });

        }

    }
);


// =====================================================
// ELIMINAR REGISTRO
// DELETE /api/records/:id
// =====================================================
//
// Solo ADMIN puede eliminar.
// =====================================================

router.delete(
    "/:id",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

            const id =
                req.params.id;


            // -----------------------------------------
            // BUSCAR
            // -----------------------------------------

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


            // -----------------------------------------
            // ELIMINAR
            // -----------------------------------------

            db.prepare(`
                DELETE FROM records
                WHERE id = ?
            `).run(id);


            // -----------------------------------------
            // AUDITORÍA
            // -----------------------------------------

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


        } catch (error) {

            console.error(
                "Error eliminando registro:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo eliminar el registro"

            });

        }

    }
);


module.exports = router;
