package es.secdevoops.springboot.jwt.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    protected final Log logger = LogFactory.getLog(this.getClass());

    @Value("${spring.security.jwt.secret}")
    private String secretKey;
    private final JwtService jwtService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // Get the authorization header from the request
        String authorizationHeader = request.getHeader("Authorization");

        // If the authorization header is missing or not in the correct format, proceed with the filter chain
        if (StringUtils.isEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
            return;
        }

        // Extract the JWT token from the authorization header
        String token = authorizationHeader.replace("Bearer ", "");

        try {
            // Validate the JWT token
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            // Get the username and authorities from the JWT token
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            String username = claims.getSubject();

            // Check if the token is still valid
            if (!jwtService.isTokenValid(token, username)) {
                logger.error("Invalid JWT token: {}");
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                return;
            }
            jwtService.invalidateToken(username);
        } catch (JwtException e) {
            // Handle JWT validation errors
            logger.error("Error validating JWT token: {}");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }
    }
}