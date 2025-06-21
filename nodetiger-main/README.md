# Nodetiger
* JWT based Sportskeyz auth service.

# Description
* The backend services for handling an authentication and authorization for different API's like signin/signup, OTP verification, forgot-password, reset-password and custom OAuth2 API's.


## API Endpoints

### Create User (aka Sign Up a User)

To create a new user, `POST /register` with the payload:

```json
{
  "phone": "9999999999",
  "password": "12345678"
}
```

#### Request

```
POST /register HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

OTP will be sent on your phone number:

```json
{
  "status": "success",
  "message": "We have sent an OTP on your phone number for verification."
}
```


### Verify an OTP for Signup

Verify an OTP for signup , `POST /verify-otp` with the payload:

```json
{
  "phone": "9999999999",
  "otp": "872973"
}
```

#### Request

```
POST /verify-otp HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

OTP verification message:

```json
{
  "status": "success",
  "message": "OTP verified successfully"
}
```


### Resent an OTP for Signup

Resent an OTP for signup , `POST /resend-otp` with the payload:

```json
{
  "phone": "9999999999"
}
```

#### Request

```
POST /resend-otp HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

Resent an OTP on your phone number:

```json
{
  "status": "success",
  "message": "We have sent an OTP on your phone number for verification."
}
```


### Signin a user

Sign in a user, `POST /login` with the payload:

```json
{
  "phone": "9999999999",
  "password": "12345678"
}
```

#### Request

```
POST /login HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

User sign in message with tokens:

```json
{
  "status": "success",
  "accessToken": "access-token",
  "refreshToken": "refresh-token",
  "message": "Logged in successfully"
}
```

### Protected Route

Authorized route, `POST /protected` with the payload:

```json
{
  "phone": "9999999999"
}
```

#### Request

```
POST /protected HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Authorization: Bearer <YOUR_SIGNED_JWT>
```

#### Response

Return an access of protected resources:

```json
{
  "status": "success",
  "message": "You have access to the protected route"
}
```

### Get tokens

Get a tokens if expired, `POST /token` with the payload:

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "refresh-token"
}
```
or

```json
{
  "grant_type": "password",
  "phone": "9999999999",
  "password": "12345678"
}
```
#### Request

```
POST /token HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

Return a tokens:

```json
{
  "status": "success",
  "accessToken": "access-token",
  "refreshToken": "refresh-token"
}
```


### Forgot Password

Forgot a password, `POST /forgot-password` with the payload:

```json
{
  "phone": "9999999999"
}
```

#### Request

```
POST /forgot-password HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

Sent an OTP if phone exist and return blank object:

```json
{}
```


### Recover Password Through OTP Verification

Recover password, `POST /verify` with the payload:

```json
{
  "phone": "9999999999",
  "otp": "116842"
}
```

#### Request

```
POST /verify HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

Return a tokens:

```json
{
  "status": "success",
  "accessToken": "access-token",
  "refreshToken": "refresh-token"
}
```


### Reset Password

Reset a password, `POST /reset-password` with the payload:

```json
{
  "phone": "9999999999",
  "password": "12345678"
}
```

#### Request

```
POST /reset-password HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Authorization: Bearer <YOUR_SIGNED_JWT>
```

#### Response

Reset a password response:

```json
{
  "status": "success",
  "message": "Password reset successfully"
}
```


### Logout the user

Logout a user, `POST /logout` with the payload:

```json
{}
```

#### Request

```
POST /logout HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

Logout an user:

```json
{
  "status": "success",
  "message": "Log out successfully"
}
```


## Custom OAuth API Endpoints

### Set a Client

Set a client, `POST /oauth/set_client` with the payload:

```json
{
  "clientId": "client-id",
  "clientSecret": "client-secret",
  "redirectUri": "http://localhost:3000/callback",
  "grants": [
    "authorization_code",
    "refresh_token",
    "password"
  ],
  "scopes": [
    "phone",
    "profile",
    "email",
    "openid"
  ]
}
```

#### Request

```
POST /oauth/set_client HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

Response after creating a client:

```json
{
  "status": "success",
  "createdClient": {
    "id": "id",
    "clientId": "client-id",
    "clientSecret": "client-secret",
    "callbackUrl": "http://localhost:3000/callback",
    "grants": [
      "authorization_code",
      "refresh_token",
      "password"
    ],
    "scopes": [
      "phone",
      "profile",
      "email",
      "openid"
    ],
    "updatedAt": "2023-08-28T10:44:45.733Z",
    "createdAt": "2023-08-28T10:44:45.733Z",
    "userId": "user-id"
  }
}
```

### Authorisation request for getting a code

For getting a code, `GET /oauth/authorize` with the payload:

```json
https://localhost:3000/oauth/authorize?response_type=code&client_id=client-id&redirect_uri=http://localhost:3000/callback&scope=phone profile email openid&state=state&code_challange=code-challange&code_challange_method=S256
```

#### Request

```
GET /oauth/authorize HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

#### Response

Response with authorization code:

```json
{
  "authorizationCode": "authorization-code",
  "expiresAt": "2023-08-28T10:56:27.634Z",
  "redirectUri": "http://localhost:3000/callback",
  "scope": "phone profile email openid",
  "clientId": "client-id",
  "userId": "user-id"
}
```

### Getting access token

For getting an access token, `POST /oauth/token` with the payload:

```json
{
  "grant_type": "authorization-code", // password, refresh-token
  "code": "2023-08-28T10:56:27.634Z",
  "client_id": "http://localhost:3000/callback",
  "client_secret": "phone profile email openid",
  "redirect_uri": "client-id",
  "refresh_token": "user-id",
  "code_verifier": "code-verifier",
  "refresh-token": "refresh-token", // Required if grant_type is refresh-token
  "username": "username", // Required if grant_type is password
  "password": "password"  // Required if grant_type is password
}
```

#### Request

```
POST /oauth/set_client HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/x-www-form-urlencoded
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Authorization: Basic Auth <Username : client_id> <Password : client_secret>
```

#### Response

Getting an access token:

```json
{
  "accessToken": "access-token",
  "token_type": "bearer",
  "accessTokenExpiresAt": "2023-08-28T12:29:01.988Z",
  "refreshToken": "refresh-token",
  "refreshTokenExpiresAt": "2023-08-29T11:29:01.995Z",
  "scope": "phone profile email openid",
  "client": {
    "id": "client-id"
  },
  "user": {
    "id": "user-id"
  },
  "id_token": "id-token"
}
```


### Protected Route

For getting an access of authorize resource , `GET /oauth/authenticate` with the payload:

```json
{}
```

#### Request

```
GET /oauth/authenticate HTTP/1.1
Host: localhost:3000
User-Agent: PostmanRuntime/7.29.3
Content-Type: application/json
Accept: */*
Content-Length: 57
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Authorization: Bearer <YOUR_SIGNED_JWT>
```

#### Response

Getting a response from authorize resouce:

```json
{
  "id": "user-id",
  "email": null,
  "phone": "9999999999"
}
```