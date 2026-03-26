const isAdmin = (req, res, next) => {
const fs = require('fs');

function logSecurityEvent(message) {

    const log = `${new Date().toISOString()} - ${message}\n`;

    fs.appendFile('security.log', log, () => {});

}




    if (!req.user || req.user.role !== "admin") {

        logSecurityEvent(`Tentative admin refusée pour user ${req.user?.email}`);

        return res.status(403).json({
            error: "Accès refusé"
        });
    }

    next();
};

module.exports = isAdmin;