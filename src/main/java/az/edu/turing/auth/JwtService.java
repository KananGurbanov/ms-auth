package az.edu.turing.auth;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String secretKey = "082dd5eb9242b59f90eaeeef10e148fe13209a12f8162170de3cd452453ad4eb";
    private static final long expirationTime = 86400000;
    private static final long refreshTokenExpirationTime = 14 * 86400000;

    public String extractUserId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(String userId) {
        return generateToken(new HashMap<>(), userId);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            String userId
    ) {
        return buildToken(extraClaims, userId, expirationTime);
    }

    public String generateRefreshToken(
            String userId
    ) {
        return buildToken(new HashMap<>(), userId, refreshTokenExpirationTime);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            String userId,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userId)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, Long userId) {
        final String id = extractUserId(token);
        return (id.equals(userId.toString())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Token has expired", e);
        } catch (SignatureException e) {
            throw new RuntimeException("Invalid token signature", e);
        } catch (MalformedJwtException e) {
            throw new RuntimeException("Malformed token", e);
        }catch (JwtException e) {
            throw new RuntimeException("Token is invalid", e);
        }
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
