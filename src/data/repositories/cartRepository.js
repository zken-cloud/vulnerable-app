const db = {
    'cart-123': { id: 'cart-123', items: ['item1'], totalPrice: 100.0, appliedPromos: [] }
};

exports.getCart = (cartId) => {
    return db[cartId] || null;
};

exports.saveCart = (cartId, cartObj) => {
    db[cartId] = cartObj;
};