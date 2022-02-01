const jwt = require('jsonwebtoken');

const createJWT = ({ payload }) => {
  const token = jwt.sign(payload, process.env.JWT_SECRET);
  return token;
};

const isTokenValid = ( token ) => jwt.verify(token, process.env.JWT_SECRET);

const attachCookiesToResponse = ({ res, user , refreshToken }) => {
  const accessTokenJWT = createJWT({ payload: {user} });
  const refreshTokenJWT = createJWT({payload:{ user , refreshToken }})

  const oneDay = 1000 * 60 * 60 * 24 ;
  const longerExpiration = 60 * 1000 * 60 * 24 *30        // 30 days :)

  res.cookie('accessToken', accessTokenJWT, { 
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    signed: true,
    maxAge:oneDay ,      // property in miliseconds
  });
  res.cookie('refreshToken', refreshTokenJWT, {
    httpOnly:true,
    secure:process.env.NODE_ENV === 'production',
    signed:true,
    expires: new Date(Date.now() + longerExpiration)
  })
};
//const attachSungleCookieToResponse = ({ res, user }) => {
//  const token = createJWT({ payload: user });

 // const oneDay = 1000 * 60 * 60 * 24;
//  const fiveSeconds = 5 * 1000

  //res.cookie('token', token, {
 //   httpOnly: true,
 //   expires: new Date(Date.now() + fiveSeconds),
  //  secure: process.env.NODE_ENV === 'production',
  //  signed: true,
 // });
//};

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse,
};
