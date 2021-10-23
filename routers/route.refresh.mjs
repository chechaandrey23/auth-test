import bcrypt from 'bcryptjs';

import {Router} from 'express';
import {validationResult, body} from 'express-validator';

import {AppError} from '../app.error.mjs';
import {getConnectMDB, MongoServerError, ObjectId} from '../mdb.mjs';
import {genAccessJWT, genRefreshJWT, validRefreshJWT, validAccessJWT} from '../jwt.mjs';

import {SALT_ROUNDS, SALT_SECRET_1, SALT_SECRET_2} from '../configs/config.password.mjs';
import {JWT_REFRESH_EXPIRES_IN} from '../configs/config.jwt.mjs';

export async function routeRefresh(req, res) {
	const MDBConnect = getConnectMDB();
	
	const {refreshToken: originRefreshToken} = req.cookies;
	
	console.log(`Refresh with refresh token: ${originRefreshToken}`);
	
	let obj = await MDBConnect.collection('r_tokens').findOne({refreshToken: originRefreshToken, expiresAt: {$gt: Date.now()}});
	
	if(!obj) {
		// redirect to login/registration
		return res.status(403).json({message: `User with refresh token ${originRefreshToken} - NOT EXISTS`});
	}
	
	const payload = validRefreshJWT(obj.refreshToken);
	
	if(!payload) {
		// redirect to login/registration
		return res.status(403).json({message: `User with refresh token ${obj.refreshToken} - NOT VALIDATED!!!`});
	}
	
	console.log(payload.email, obj.user);
	let user = await MDBConnect.collection('users').findOne({email: payload.email, _id: ObjectId(obj.user)});
	
	if(!user) {
		return res.status(500).json({message: `User with email "${payload.email}" and _id "${obj.user}" - NOT EXISTS`});
	}
	let userId = user._id.toString();
	
	const accessToken = genAccessJWT({email: user.email, userId});
	const refreshToken = genRefreshJWT({email: user.email, userId});
	
	// save refresh token
	await MDBConnect.collection('r_tokens').updateOne(
		{user: userId}, 
		{$set: {refreshToken, expiresAt: Date.now() + (JWT_REFRESH_EXPIRES_IN * 1000)}}, 
		{upsert: true}
	);
	
	res.cookie('refreshToken', refreshToken, {maxAge: JWT_REFRESH_EXPIRES_IN*1000/*, httpOnly: true*/});
	
	return res.json({type: 'success_refresh', message: `User with refresh token "${originRefreshToken}" refresh success`, token: accessToken});
}
