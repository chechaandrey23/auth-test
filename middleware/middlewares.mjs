import {genAccessJWT, genRefreshJWT, validRefreshJWT, validAccessJWT} from '../jwt.mjs';

export function middlewareChechAccessToken(req, res, next) {
	const authorizationHeader = req.headers.authorization;
	if(!authorizationHeader) {
		return res.status(500).json({message: 'Headers "authorization" - not exists'});
	}
	
	let chunks = authorizationHeader.split(' ');
	
	if(chunks[0] != 'Bearer') {
		return res.status(500).json({message: 'Header authorization is not a Bearer authorization'});
	}
	
	if(!chunks[1]) {
		return res.status(500).json({message: 'Header Bearer authorization incorrect!!!'});
	}
	
	const accessPayload = validAccessJWT(chunks[1]);
	
	if(!accessPayload) {
		return res.status(401).json({message: `User with access token ${chunks[1]} - NOT VALIDATED!!!`});
	}
	
	next();
}

export function middlewareChechRefreshToken(req, res, next) {
	const {refreshToken} = req.cookies;
	
	if(!refreshToken) {
		return res.status(403).json({message: `Refresh token - not exists!`});
	}
	
	const refreshPayload = validRefreshJWT(refreshToken);
	
	if(!refreshPayload) {
		return res.status(403).json({message: `Refresh token "${refreshToken}" - incorrect!`});
	}
	
	next();
}
