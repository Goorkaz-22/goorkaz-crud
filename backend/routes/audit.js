const express = require("express");

const db = require("../database");

const {
    authenticateToken,
    requireRole
} = require("../middleware/auth");

const router = express.Router();


// =====================================================
// LISTAR AUDITORÍA
// GET /api/audit
// =====================================================

router.get(
    "/",
    authenticateToken,
    requireRole("admin"),
    (req, res) => {

        try {

            const logs =
                db.prepare(`
                    SELECT
                        audit_logs.id,
                        audit_logs.action,
                        audit_logs.record_id,
                        audit_logs.description,
                        audit_logs.created_at,
                        users.name AS user_name,
                        users.email AS user_email
                    FROM audit_logs
                    LEFT JOIN users
                        ON users.id = audit_logs.user_id
                    ORDER BY audit_logs.id DESC
                `).all();


            res.json({

                success: true,

                logs

            });


        } catch (error) {

            console.error(
                "Error obteniendo auditoría:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "No se pudo obtener la auditoría"

            });

        }

    }
);


module.exports = router;
