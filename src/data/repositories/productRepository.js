const productCatalog = [
  { id: '1', type: 'electronics', name: 'Laptop', inStock: true, price: 999 },
  { id: '2', type: 'apparel', name: 'T-Shirt', inStock: true, price: 20 },
  { id: '3', type: 'internal', name: 'Internal Config', price: 0 }
];

exports.filterProducts = (query) => {
    // Vulnerability 13: Logical Syntax Injection
    return productCatalog.filter(doc => {
        for (let k in query) {
            if (typeof query[k] === 'object' && query[k] !== null) {
                if (query[k]['$ne'] !== undefined && doc[k] !== query[k]['$ne']) return true;
                if (query[k]['$in'] !== undefined && query[k]['$in'].includes(doc[k])) return true;
            } else if (doc[k] !== query[k]) return false;
        }
        return true;
    });
};