import jwt from 'jsonwebtoken';

import {JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, JWT_REFRESH_EXPIRES_IN} from './configs/config.jwt.mjs';

export function genAccessJWT(payload) {
	return jwt.sign(payload, JWT_ACCESS_SECRET, {expiresIn: getRandomArbitrary(30, 60+1)});
}

export function genRefreshJWT(payload) {
	return jwt.sign(payload, JWT_ACCESS_SECRET, {expiresIn: JWT_REFRESH_EXPIRES_IN});
}

function getRandomArbitrary(min, max) {
	return Math.round(Math.random() * (max - min) + min);
}

export function validAccessJWT(token) {
	try {
		return jwt.verify(token, JWT_ACCESS_SECRET);
	} catch (e) {
		return null;
	}
}

export function validRefreshJWT(token) {
	try {
		return jwt.verify(token, JWT_ACCESS_SECRET);
	} catch (e) {
		return null;
	}
}
