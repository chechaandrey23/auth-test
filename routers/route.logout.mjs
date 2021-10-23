import bcrypt from 'bcryptjs';

import {Router} from 'express';
import {validationResult, body} from 'express-validator';

import {AppError} from '../app.error.mjs';
import {getConnectMDB, MongoServerError, ObjectId} from '../mdb.mjs';
import {genAccessJWT, genRefreshJWT, validRefreshJWT, validAccessJWT} from '../jwt.mjs';

import {SALT_ROUNDS, SALT_SECRET_1, SALT_SECRET_2} from '../configs/config.password.mjs';
import {JWT_REFRESH_EXPIRES_IN} from '../configs/config.jwt.mjs';

export async function routeLogout(req, res) {
	const MDBConnect = getConnectMDB();
	
	const {refreshToken} = req.cookies;
	
	console.log(`Logout with refresh token: ${refreshToken}`);
	
	let obj = await MDBConnect.collection('r_tokens').findOneAndDelete({refreshToken});
	
	if(!obj.value) {
		return res.status(500).json({message: `User with token ${refreshToken} - NOT EXISTS`});
	}
	
	let token = obj.value.refreshToken;
	
	res.clearCookie('refreshToken');
	return res.json({type: 'success_logout', message: `Refresh token ${token} delete success`});
}
