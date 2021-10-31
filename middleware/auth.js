const jwt = require('jsonwebtoken')


const verifyToken = (req, res, next)=> {
    try {
        const token = req.headers['x-access-token']

    if(!token) {
        return res.status(403).send('Token is required for authentication')
    }
    
        const decoded = jwt.verify(token, process.env.TOKEN_KEY)
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).send('Invalid token')
    }
    
}

module.exports = verifyToken