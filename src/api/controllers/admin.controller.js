const adminService = require('../../services/admin.service');

exports.checkShippingStatus = (req, res) => {
    adminService.pingProvider(req.body.providerIP, req.body.options, out => res.send({ logs: out })); // Vuln 5 Sink
};

exports.previewDynamicPricing = (req, res) => {
    try {
        res.json({ price: adminService.evaluateDiscount(req.body.formula) }); // Vuln 7 Sink
    } catch (e) {
        res.status(400).send("Evaluation Failed");
    }
};