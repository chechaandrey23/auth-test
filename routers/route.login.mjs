import bcrypt from 'bcryptjs';

import {Router} from 'express';
import {validationResult, body} from 'express-validator';

import {AppError} from '../app.error.mjs';
import {getConnectMDB, MongoServerError, ObjectId} from '../mdb.mjs';
import {genAccessJWT, genRefreshJWT, validRefreshJWT, validAccessJWT} from '../jwt.mjs';

import {SALT_ROUNDS, SALT_SECRET_1, SALT_SECRET_2} from '../configs/config.password.mjs';
import {JWT_REFRESH_EXPIRES_IN} from '../configs/config.jwt.mjs';

export async function routeLogin(req, res) {
	const MDBConnect = getConnectMDB();
	
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		res.status(400).json({message: 'validation errors', errors: errors.array()});
	}
	const {email, password} = req.body;
	
	let user = await MDBConnect.collection('users').findOne({email});
	
	if(!user) {
		return res.status(400).json({message: `User with email "${email}" - NOT EXISTS`});
	}
	
	const isPassEquals = await bcrypt.compare(SALT_SECRET_1 + password + SALT_SECRET_2, user.hashPassword);
	
	if(!isPassEquals) {
		return res.status(400).json({message: `Password is incorrect`});
	}
	
	let userId = user._id.toString();
	
	const accessToken = genAccessJWT({email, userId});
	const refreshToken = genRefreshJWT({email, userId});
	
	// save refresh token
	await MDBConnect.collection('r_tokens').updateOne(
		{user: userId}, 
		{$set: {refreshToken, expiresAt: Date.now() + (JWT_REFRESH_EXPIRES_IN * 1000)}}, 
		{upsert: true}
	);
	
	res.cookie('refreshToken', refreshToken, {maxAge: JWT_REFRESH_EXPIRES_IN*1000/*, httpOnly: true*/})
	
	return res.json({type: 'success_login', message: `User with email "${email}" login success`, token: accessToken});
}
