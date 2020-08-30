from pydantic import BaseModel
from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt, JWTError
import time
import logging
from ecdsa import SigningKey, BRAINPOOLP256r1
from os import path

loggar = logger = logging.getLogger(__name__)  

ISSUER='https://id.acme.spilikin.dev/'
TOKEN_VALIDITY_PERIOD=60*60*24 # 24 Hours

if not path.exists('.db/idp_verifying_key.pem') or not path.exists('.db/idp_signing_key.pem'):
    sk = SigningKey.generate(curve=BRAINPOOLP256r1)
    # write signing and verifying keys to files
    open(f'.db/idp_signing_key.pem', 'w+b').write(sk.to_pem())
    open(f'.db/idp_verifying_key.pem', 'w+b').write(sk.verifying_key.to_pem())

PRIVATE_KEY=open(f'.db/idp_signing_key.pem').read()
PUBLIC_KEY=open(f'.db/idp_verifying_key.pem').read()

oauth2 = OAuth2AuthorizationCodeBearer(authorizationUrl='auth', tokenUrl='token')

class User(BaseModel):
    acct: str

def get_remote_user(token: str = Depends(oauth2)):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, PUBLIC_KEY, options={'verify_aud': False})
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        credentials_exception.detail=str(e)
        raise credentials_exception
    
    return User(acct=username)

def impersonate(acct: str):
    return issue_token(acct)

def issue_token(acct: str, audience = None):
    token_data = {
        'iss': ISSUER,
        'sub': acct,
        'exp': int(time.time())+TOKEN_VALIDITY_PERIOD
    }
    if audience:
        token_data['aud'] = audience
    token = jwt.encode(token_data, PRIVATE_KEY, algorithm='ES256')
    return token
