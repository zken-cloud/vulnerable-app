const discountService = require('../../services/discount.service');

exports.applyDiscount = (req, res) => {
    try {
        const updatedCart = discountService.applyPromoToCart(req.body.cartId, req.body.promoCode);
        res.json(updatedCart);
    } catch (e) {
        res.status(400).send(e.message);
    }
};