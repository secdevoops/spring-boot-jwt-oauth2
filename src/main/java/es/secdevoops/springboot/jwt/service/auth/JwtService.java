package es.secdevoops.springboot.jwt.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
private final String issuer;
private final Long expirationTime;
private final String secretKey;

private Map<String, String> validTokenMap =  new HashMap<>();

    @Autowired
    public JwtService(@Value("${spring.security.jwt.issuer}") String issuer,
        @Value("${spring.security.jwt.expiration-time}") Long expirationTime,
        @Value("${spring.security.jwt.secret}") String secretKey) {
        this.issuer = issuer;
        this.expirationTime = expirationTime;
        this.secretKey = secretKey;
    }


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    public String generateToken(UserDetails userDetails) {
        String token = generateToken(new HashMap<>(), userDetails);
        validTokenMap.put(userDetails.getUsername(), token);
        return token;
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        extraClaims.put("roles", userDetails.getAuthorities());
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())).setIssuer(issuer)
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    public void invalidateToken(String username) {
        // Invalid JWT token from cache
        validTokenMap.remove(username);
    }


    public boolean isTokenValid(String token, String username) {
        final String tokenUsername = extractUsername(token);
        final String validToken = validTokenMap.get(username);
        return (tokenUsername.equals(username)) && !isTokenExpired(token) &&  validToken != null && validToken.equals(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public long getExpirationTime() {
        return this.expirationTime;
    }
}