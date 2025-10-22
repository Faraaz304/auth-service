# Refresh Token Implementation

## Summary
Successfully implemented refresh token functionality with 7-day expiration:

### Changes Made:
1. **AuthService Interface**: Added `refreshToken(String refreshToken)` method
2. **JwtService**: Added `generateRefreshToken()` and `validateRefreshToken()` methods
3. **AuthResponse DTO**: Added `refreshToken` field
4. **AuthServiceImpl**: Fixed refresh token implementation with proper validation
5. **AuthController**: Refresh endpoint already existed, now works correctly

### Key Features:
- **Access Token**: 24 hours expiration (as configured)
- **Refresh Token**: 7 days expiration
- **Security**: Refresh tokens are validated separately from access tokens
- **Token Rotation**: New refresh token generated on each refresh

### API Usage:

#### 1. Login/Register Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "email": "user@example.com",
  "role": "USER"
}
```

#### 2. Refresh Token Request:
```bash
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9..."
}
```

#### 3. Refresh Token Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "email": "user@example.com",
  "role": "USER"
}
```

### Security Notes:
- Refresh tokens contain a "type": "refresh" claim for validation
- Refresh tokens cannot be used as access tokens
- Both tokens are rotated on refresh for enhanced security