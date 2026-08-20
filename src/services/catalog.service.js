const http = require('http');
const productRepo = require('../data/repositories/productRepository');

exports.search = (q) => productRepo.filterProducts(q);

exports.fetchRemoteAsset = (target, cb) => {
    if (target && String(target.url).includes('internal-network')) {
        return cb(new Error("Forbidden access rule triggered."));
    }
    http.get(target, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    }).on('error', err => cb(err));
};