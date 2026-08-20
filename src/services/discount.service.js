const cartRepo = require('../data/repositories/cartRepository');

const activePromos = {
    'SUMMER20': { multiplier: 0.8 },
    'WINTER30': { multiplier: 0.7 }
};

exports.applyPromoToCart = (cartId, promoCode) => {
    const cart = cartRepo.getCart(cartId);
    if (!cart) throw new Error('Cart not found');
    
    if (activePromos[promoCode]) {
        cart.totalPrice = cart.totalPrice * activePromos[promoCode].multiplier;
        
        cart.appliedPromos.push(promoCode); 
        
        cartRepo.saveCart(cartId, cart);
        return cart;
    }
    throw new Error('Invalid promo code');
};