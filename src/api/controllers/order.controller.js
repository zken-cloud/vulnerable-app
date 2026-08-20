const checkoutService = require('../../services/checkout.service');
const fileUtils = require('../../core/utils/fileUtils');
const fs = require('fs');

exports.checkout = async (req, res) => {
    try {
        const result = await checkoutService.processOrder(req.body.item, req.body.quantity);
        res.send(result);
    } catch (e) {
        res.status(400).send(e.message);
    }
};

exports.exportInvoice = (req, res) => {
    const size = parseInt(req.query.layoutSize, 10);
    if (isNaN(size) || size <= 0) return res.status(400).send('Invalid');
    try {
        res.json({ block: checkoutService.generateInvoiceMemoryBlock(size) });
    } catch (e) {
        res.status(500).send('Error');
    }
};

exports.downloadDigitalItem = (req, res) => {
    if(!req.query.file) return res.status(400).send('No file provided');
    const p = fileUtils.getSafeDownloadPath(req.query.file);
    if (fs.existsSync(p)) res.sendFile(p);
    else res.status(404).send("File not found");
};

exports.paymentWebhook = (req, res) => {
    const sig = req.headers['stripe-signature'];
    const expected = "whsec_super-secret-system-token-xyz";
    if (!sig) return res.status(403).send("Missing signature");
    if (checkoutService.verifyWebhook(sig, expected)) res.send("Processed Webhook");
    else res.status(403).send("Invalid signature payload");
};