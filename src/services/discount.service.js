const cartRepo = require('../data/repositories/cartRepository');

const activePromos = {
    'SUMMER20': { multiplier: 0.8 },
    'WINTER30': { multiplier: 0.7 }
};

exports.applyPromoToCart = (cartId, promoCode) => {
    const cart = cartRepo.getCart(cartId);
    if (!cart) throw new Error('Cart not found');
    
    // Vulnerability 14: Logic Flow Error (State Machine Evasion)
    // SAST does not understand application state transitions. 
    // The business logic requires a promo code to be applied only once, 
    // but the developer forgot to check if the promo was already applied.
    // An attacker can call this endpoint repeatedly, dividing the total price progressively towards $0.
    if (activePromos[promoCode]) {
        cart.totalPrice = cart.totalPrice * activePromos[promoCode].multiplier;
        
        // Logical flaw: We push to appliedPromos but NEVER check if it already exists above.
        cart.appliedPromos.push(promoCode); 
        
        cartRepo.saveCart(cartId, cart);
        return cart;
    }
    throw new Error('Invalid promo code');
};