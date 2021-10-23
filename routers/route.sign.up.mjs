import bcrypt from 'bcryptjs';

import {Router} from 'express';
import {validationResult, body} from 'express-validator';

import {AppError} from '../app.error.mjs';
import {getConnectMDB, MongoServerError, ObjectId} from '../mdb.mjs';
import {genAccessJWT, genRefreshJWT, validRefreshJWT, validAccessJWT} from '../jwt.mjs';

import {SALT_ROUNDS, SALT_SECRET_1, SALT_SECRET_2} from '../configs/config.password.mjs';
import {JWT_REFRESH_EXPIRES_IN} from '../configs/config.jwt.mjs';

export async function routeSignUp(req, res) {
	const MDBConnect = getConnectMDB();
	
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(400).json({message: 'validation errors', errors: errors.array()});
	}
	const {email, password} = req.body;
	
	const hashPassword = await bcrypt.hash(SALT_SECRET_1 + password + SALT_SECRET_2, SALT_ROUNDS);
	
	let userId = null;
	try {
		let resInsert = await MDBConnect.collection('users').insertOne({email, hashPassword});
		userId = resInsert.insertedId.toString();
	} catch(e) {
		if(e instanceof MongoServerError && e.code === 11000) {
			return res.status(400).json({message: `User with email "${email}" already exists`});
		} else {
			throw e;
		}
	}
	
	return res.json({type: 'success_registration', message: `User with email "${email}" registration success`});
	
	/*
	const accessToken = genAccessJWT({email, userId});
	const refreshToken = genRefreshJWT({email, userId});
	
	// save refresh token
	await MDBConnect.collection('r_tokens').updateOne(
		{user: user._id}, 
		{$set: {refreshToken, expiresAt: Date.now() + (JWT_REFRESH_EXPIRES_IN * 1000)}}, 
		{upsert: true}
	);
	
	res.cookie('refreshToken', refreshToken, {maxAge: JWT_REFRESH_EXPIRES_IN*1000/*, httpOnly: true* /});
	
	return res.json({type: 'success_registration', message: `User with email "${email}" registration success`, token: accessToken});
	*/
}
