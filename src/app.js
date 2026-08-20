const express = require('express');
const bodyParser = require('body-parser');
const routes = require('./api/routes/v1');
const tracking = require('./api/middlewares/tracking.middleware');
const app = express();

app.use(bodyParser.json());
app.use(tracking);
app.use('/api/v1', routes);

module.exports = app;