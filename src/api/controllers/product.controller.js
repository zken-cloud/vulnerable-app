const catalogService = require('../../services/catalog.service');
const fs = require('fs');
const mediaCache = require('../../core/cache/mediaCache');

exports.searchProducts = (req, res) => {
    res.json(catalogService.search(req.body.query));
};

exports.importImage = (req, res) => {
    catalogService.fetchRemoteAsset(req.body.target, (err, data) => {
        if (err) res.status(400).send(err.message);
        else res.send(data);
    });
};

exports.cacheHeader = (req, res) => {
    // Creates a dummy temporary file mimicking a file upload
    const dummyPath = '/tmp/fake_large_media_' + Date.now() + '.pdf';
    fs.writeFileSync(dummyPath, Buffer.alloc(5 * 1024 * 1024, 'A')); // 5MB dummy file
    
    // Processes the media and caches its header
    const fileId = req.body.fileId || Date.now().toString();
    const headerHex = mediaCache.extractAndCacheHeader(dummyPath, fileId);
    
    // Clean up file
    fs.unlinkSync(dummyPath);
    
    res.json({ message: "Media header cached.", fileId, headerHex });
};