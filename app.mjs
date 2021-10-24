import {Router} from 'express';

import {validationResult, body} from 'express-validator';

import {middlewareChechRefreshToken, middlewareChechAccessToken} from './middleware/middlewares.mjs';

import {routeSignUp} from './routers/route.sign.up.mjs';
import {routeLogin} from './routers/route.login.mjs';
import {routeLogout} from './routers/route.logout.mjs';
import {routeRefresh} from './routers/route.refresh.mjs';
import {routeMe} from './routers/route.me.mjs';

const routers = new Router();

routers.post('/sign_up', body('email').isEmail(), body('password').isLength({min: 3, max: 32}), routeSignUp);
routers.post('/login', body('email').isEmail(), body('password').isLength({min: 3, max: 32}), routeLogin);
routers.post('/logout', middlewareChechRefreshToken, middlewareChechAccessToken, routeLogout);
routers.post('/refresh', middlewareChechRefreshToken, routeRefresh);
routers.get('/me:chunk', middlewareChechRefreshToken, middlewareChechAccessToken, routeMe);

export {routers};
