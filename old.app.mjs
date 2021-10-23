import bcrypt from 'bcryptjs';

import {Router} from 'express';
import {validationResult, body} from 'express-validator';

import {AppError} from './app.error.mjs';
import {getConnectMDB, MongoServerError, ObjectId} from './mdb.mjs';
import {genAccessJWT, genRefreshJWT, validRefreshJWT, validAccessJWT} from './jwt.mjs';
import {middlewareChechRefreshToken, middlewareChechAccessToken} from './middlewares.mjs';

import {SALT_ROUNDS, SALT_SECRET_1, SALT_SECRET_2} from './configs/config.password.mjs';
import {JWT_REFRESH_EXPIRES_IN} from './configs/config.jwt.mjs';

const routers = new Router();

routers.post('/sign_up', body('email').isEmail(), body('password').isLength({min: 3, max: 32}), async (req, res) => {
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
});

routers.post('/login', body('email').isEmail(), body('password').isLength({min: 3, max: 32}), async (req, res) => {
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
		{user: user._id}, 
		{$set: {refreshToken, expiresAt: Date.now() + (JWT_REFRESH_EXPIRES_IN * 1000)}}, 
		{upsert: true}
	);
	
	res.cookie('refreshToken', refreshToken, {maxAge: JWT_REFRESH_EXPIRES_IN*1000/*, httpOnly: true*/})
	
	return res.json({type: 'success_login', message: `User with email "${email}" login success`, token: accessToken});
});

routers.post('/logout', middlewareChechRefreshToken, async (req, res) => {
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
});

routers.post('/refresh', middlewareChechRefreshToken, async (req, res) => {
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
});

routers.get('/me:chunk', middlewareChechRefreshToken, middlewareChechAccessToken, async(req, res) => {
	const MDBConnect = getConnectMDB();
	
	let chunk = req.params?req.params.chunk:null;
	
	let rawAccessToken = req.headers.authorization;
	rawAccessToken = rawAccessToken.split(' ')[1];
	
	const accessPayload = validAccessJWT(rawAccessToken);
	
	let rawRefreshToken = req.cookies.refreshToken;
	
	const refreshPayload = validRefreshJWT(rawRefreshToken);
	
	return res.json({type: 'success_get', chunk, accessPayload, refreshPayload});
});

export {routers};
