# Enterprise E-Commerce API

A modular Node.js / Express REST API for a small e-commerce backend, organised in a
layered architecture: routes → controllers → services → repositories, with shared
utilities and middleware.

## Running the Application

```bash
npm install
npm start
```

The server binds to port 3000. All routes are mounted under `/api/v1`.

## Project Layout

```
src/
├── server.js                 Entry point
├── app.js                    Express app + middleware wiring
├── api/
│   ├── routes/v1/            Route definitions
│   ├── controllers/          Request handlers (user, product, order, discount, admin)
│   └── middlewares/          Auth, validation, request tracking
├── services/                 Business logic (auth, catalog, checkout, discount, admin)
├── data/repositories/        In-memory data access (users, products, cart)
└── core/
    ├── utils/                Crypto, data, file and system helpers
    └── cache/                Media header cache
```

## Endpoints (selected)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/user/register` | Register a corporate user |
| PUT  | `/api/v1/user/profile/:id` | Update a user profile |
| POST | `/api/v1/products/search` | Search the catalog |
| POST | `/api/v1/cart/checkout` | Check out the cart |
| POST | `/api/v1/cart/apply-discount` | Apply a promo code |
| GET  | `/api/v1/order/invoice` | Download an invoice |
| POST | `/api/v1/admin/calculate-discount` | Preview dynamic pricing (admin) |

## License

Private — internal demo project.
