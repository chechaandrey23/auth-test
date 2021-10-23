import bcrypt from 'bcryptjs';

import {Router} from 'express';
import {validationResult, body} from 'express-validator';

import {AppError} from '../app.error.mjs';
import {getConnectMDB, MongoServerError, ObjectId} from '../mdb.mjs';
import {genAccessJWT, genRefreshJWT, validRefreshJWT, validAccessJWT} from '../jwt.mjs';

import {SALT_ROUNDS, SALT_SECRET_1, SALT_SECRET_2} from '../configs/config.password.mjs';
import {JWT_REFRESH_EXPIRES_IN} from '../configs/config.jwt.mjs';

export async function routeMe(req, res) {
	const MDBConnect = getConnectMDB();
	
	let chunk = req.params?req.params.chunk:null;
	
	let rawAccessToken = req.headers.authorization;
	rawAccessToken = rawAccessToken.split(' ')[1];
	
	const accessPayload = validAccessJWT(rawAccessToken);
	
	let rawRefreshToken = req.cookies.refreshToken;
	
	const refreshPayload = validRefreshJWT(rawRefreshToken);
	
	return res.json({type: 'success_get', chunk, accessPayload, refreshPayload});
}
