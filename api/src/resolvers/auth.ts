import { dbQuery } from '../services/db';
import {
  ERROR_DB_UPDATE,
  ERROR_INVALID_CREDENTIALS,
  ERROR_INVALID_INPUT,
  ERROR_NO_DB,
  ERROR_USER_UNVERIFIED,
  RESULT_OK,
  SALT_PASS_SEPARATOR,
  UserStatus,
} from '../constants';
import { getUserJWT, getUserRefreshToken, hashPassword } from '../utils/auth';
import { uuidv4 } from '../utils/misc';
import { sendEmail } from '../services/email';
import { getUserBy } from '../utils/db';
import { isEmail } from '../utils/validators';


const emailExists = async (
  db: DBConnection,
  email: string,
): Promise<boolean> => {
  const userInfo = await getUserBy(db, 'email', email);
  return typeof userInfo !== 'string';
};

// Inserts a user into the database
// Returns an empty string on success or the error message desribing problem
const addUser = async (
  db: DBConnection,
  email: string,
  password: string,
  verifyCode: string,
  firstname: string = '',
  lastname: string = '',
): Promise<OkString | string> => {
  const queryAddUser =
    `INSERT INTO tbl_user (status, email, pass, firstname, lastname, verify_code) ` +
    `VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`;

  let result = null;
  const parameters = [UserStatus.Pending, email, password, firstname, lastname, verifyCode];
  try {
    result = await dbQuery(db, queryAddUser, parameters);
    if (!result || result.rowCount !== 1) return 'could not add user';
  } catch (err) {
    return `ERROR: ${err}`;
  }

  return { value: result.rows[0]['id'] };
};

// Adds a user in the system
export const authSignup = async (input: JsonQLInput, rc: ResolverContext) => {
  if (!rc.db) return ERROR_NO_DB;

  // get input parameters
  const inputEmail = (input['email'] as string) ?? '';
  const inputPass = (input['pass'] as string) ?? '';
  if (!inputEmail || !inputPass || !isEmail(inputEmail)) return ERROR_INVALID_INPUT;

  if (await emailExists(rc.db, inputEmail))
    return { error: 'email already exists' };

  // add user
  const salt = uuidv4(false);
  const hashedPassword = hashPassword(inputPass, salt);
  const savedPassword = `${salt}${SALT_PASS_SEPARATOR}${hashedPassword}`;

  const verifyCode = uuidv4(false);

  const addResult = await addUser(
    rc.db,
    inputEmail.toLowerCase(),
    savedPassword,
    verifyCode,
  );
  if (!addResult || typeof addResult === 'string')
    return { error: `error: ${addResult}` };

  // send verification email
  sendEmail(
    inputEmail,
    'Please verify your email',
    `call API with this code to reset your password ${verifyCode}`,
  );

  return { result: addResult.value };
};

export const authVerify = async (input: JsonQLInput, rc: ResolverContext) => {
  if (!rc.db) return ERROR_NO_DB;

  // get input parameters
  const inputCode = (input['code'] as string) ?? '';
  if (!inputCode || inputCode.length !== 32) return ERROR_INVALID_INPUT;

  const userInfo = await getUserBy(rc.db, 'verify_code', inputCode);
  if (typeof userInfo === 'string') return ERROR_INVALID_INPUT;

  if (userInfo['status'] !== UserStatus.Pending) return ERROR_INVALID_INPUT;

  // set user status to verified and clear user verify code
  const queryVerifyUser = `UPDATE tbl_user SET status = '${UserStatus.Verified}', verify_code='' WHERE id = $1`

  let result1 = null;
  try {
    result1 = await dbQuery(rc.db!, queryVerifyUser, [userInfo['id']]);
    if (!result1 || result1.rowCount !== 1) return ERROR_DB_UPDATE;
  } catch (err) {
    return { error: `ERROR: ${err}` };
  }

  // add row for user details
  const queryAddUserDetails = 'INSERT INTO tbl_user_detail (id) VALUES ($1)'
  let result2 = null;
  try {
    result2 = await dbQuery(rc.db!, queryAddUserDetails, [userInfo['id']]);
    if (!result2 || result2.rowCount !== 1) return ERROR_DB_UPDATE;
  } catch (err) {
    return { error: `ERROR: ${err}` };
  }

  return RESULT_OK;
}

export const authLogin = async (input: JsonQLInput, rc: ResolverContext) => {
  if (!rc.db) return ERROR_NO_DB;

  // get input parameters
  const inputEmail = (input['email'] as string) ?? '';
  const inputPass = (input['pass'] as string) ?? '';
  if (!inputEmail || !inputPass || !isEmail(inputEmail)) return ERROR_INVALID_INPUT;

  const userInfo = await getUserBy(rc.db, 'email', inputEmail.toLowerCase());
  if (typeof userInfo === 'string') return ERROR_INVALID_CREDENTIALS;

  // compare password
  const saltPassCombined = (userInfo['pass'] ?? '') as string;
  const saltPass = saltPassCombined.split(SALT_PASS_SEPARATOR);
  const salt = saltPass[0] ?? '';
  const password = saltPass[1];

  if (hashPassword(inputPass, salt) !== password)
    return ERROR_INVALID_CREDENTIALS;

  // Check if user is activated only after password has been verified
  if (userInfo['status'] !== UserStatus.Verified) return ERROR_USER_UNVERIFIED;

  // Generate JWT and refreshToken for user
  const userId = ((userInfo['id'] ?? '') as string).replaceAll('-', '');
  const userJwt = getUserJWT(userId);
  const userRefreshToken = getUserRefreshToken(userId);

  // Save refresh token
  const querySetSession = `UPDATE tbl_user SET session = $1 WHERE id = $2`
  let result = null;
  try {
    result = await dbQuery(rc.db!, querySetSession, [userRefreshToken, userInfo['id']]);
    if (!result || result.rowCount !== 1) return ERROR_DB_UPDATE;
  } catch (err) {
    return { error: `ERROR: ${err}` };
  }

  // Get other user details
  const firstname = (userInfo['firstname'] ?? '') as string;

  return {
    result: {
      firstname: firstname,
      token: userJwt,
      refreshToken: userRefreshToken,
    },
  };
};

export const authLogout = async (input: JsonQLInput, rc: ResolverContext) => {
  if (!rc.db) return ERROR_NO_DB;
  const userId = rc.userid;
  if (!userId) return ERROR_INVALID_CREDENTIALS;

  const userInfo = await getUserBy(rc.db, 'id', userId);
  if (typeof userInfo === 'string') return ERROR_INVALID_CREDENTIALS;

  const querySetVerifyCode = `UPDATE tbl_user SET session = '' WHERE id = $1`
  let result = null;
  try {
    result = await dbQuery(rc.db!, querySetVerifyCode, [userInfo['id']]);
    if (!result || result.rowCount !== 1) return ERROR_DB_UPDATE;
  } catch (err) {
    return { error: `ERROR: ${err}` };
  }

  return RESULT_OK;
}


// Initiates sending an email to reset password
export const authForgotPassword = async (input: JsonQLInput, rc: ResolverContext) => {
  if (!rc.db) return ERROR_NO_DB;

  // get input parameters
  const inputEmail = (input['email'] as string) ?? '';
  if (!inputEmail || !isEmail(inputEmail)) return ERROR_INVALID_INPUT;

  const userInfo = await getUserBy(rc.db, 'email', inputEmail.toLowerCase());
  if (typeof userInfo === 'string') return RESULT_OK;

  const userEmail = (userInfo['email'] ?? '') as string;
  if (!userEmail) return RESULT_OK;

  // Only verified or pending verified users can perform a password reset
  if (!(userInfo['status'] === UserStatus.Verified || userInfo['status'] === UserStatus.Pending)) return RESULT_OK;

  // save unique code into user verify_code column
  const newCode = uuidv4(false);
  const querySetVerifyCode = `UPDATE tbl_user SET verify_code = $1 WHERE id = $2`
  let result = null;
  try {
    result = await dbQuery(rc.db!, querySetVerifyCode, [newCode, userInfo['id']]);
    if (!result || result.rowCount !== 1) return ERROR_DB_UPDATE;
  } catch (err) {
    return { error: `ERROR: ${err}` };
  }

  // finally send email
  await sendEmail(
    userEmail,
    'password reset',
    `call API with this code to reset your password ${newCode}`,
  );

  return RESULT_OK;
};


export const authResetPassword = async (input: JsonQLInput, rc: ResolverContext) => {
  if (!rc.db) return ERROR_NO_DB;

  // get input parameters
  const inputCode = (input['code'] as string) ?? '';
  const inputNewPass = (input['newpass'] as string) ?? '';
  if (!inputCode || !inputNewPass || inputCode.length !== 32) return ERROR_INVALID_INPUT;

  const userInfo = await getUserBy(rc.db, 'verify_code', inputCode);
  if (typeof userInfo === 'string') return ERROR_INVALID_INPUT;

  const userEmail = (userInfo['email'] ?? '') as string;
  if (!userEmail) return ERROR_INVALID_INPUT;

  const salt = uuidv4(false);
  const hashedPassword = hashPassword(inputNewPass, salt);
  const savedPassword = `${salt}${SALT_PASS_SEPARATOR}${hashedPassword}`;

  const querySetPass = `UPDATE tbl_user SET pass = $1, verify_code = '' WHERE id =$2`
  let result = null;
  try {
    result = await dbQuery(rc.db!, querySetPass, [savedPassword, userInfo['id']]);
    if (!result || result.rowCount !== 1) return ERROR_DB_UPDATE;
  } catch (err) {
    return { error: `ERROR: ${err}` };
  }

  return RESULT_OK;
}