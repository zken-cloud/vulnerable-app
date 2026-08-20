const express = require('express');
const router = express.Router();
const userController = require('../../controllers/user.controller');
const orderController = require('../../controllers/order.controller');
const productController = require('../../controllers/product.controller');
const adminController = require('../../controllers/admin.controller');
const discountController = require('../../controllers/discount.controller');
const validation = require('../../middlewares/validation.middleware');
const auth = require('../../middlewares/auth.middleware');

// User Routes
router.post('/user/register', validation.validateCorporateEmail, userController.register);
router.post('/user/forgot-password', userController.forgotPassword);
router.put('/user/profile/:id', userController.updateProfile);
router.post('/user/preferences', userController.updatePreferences);

// Product Routes
router.post('/products/search', productController.searchProducts);
router.post('/products/import-image', auth.requireAdmin, productController.importImage);
router.post('/products/process-media-header', auth.requireAdmin, productController.cacheHeader);

// Order & Cart Routes
router.post('/cart/checkout', orderController.checkout);
router.post('/cart/apply-discount', discountController.applyDiscount);
router.get('/order/invoice', orderController.exportInvoice);
router.get('/downloads', orderController.downloadDigitalItem);
router.post('/webhooks/payment', orderController.paymentWebhook);

// Admin Routes
router.post('/admin/shipping-check', auth.requireAdmin, adminController.checkShippingStatus);
router.post('/admin/calculate-discount', auth.requireAdmin, adminController.previewDynamicPricing);

module.exports = router;