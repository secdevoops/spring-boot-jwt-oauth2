package es.secdevoops.springboot.jwt.security;

import es.secdevoops.springboot.jwt.service.auth.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${spring.security.jwt.secret}")
    private String secretKey;

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Get the authorization header from the request
        String authorizationHeader = request.getHeader("Authorization");
        String token = null;

        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            // Extract the JWT token from the authorization header
            token = authorizationHeader.replace("Bearer ", "");
        }else{
            //Extract the JWT token from cookie
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals("secdevoops-token")) {
                        token = cookie.getValue();
                        break;
                    }
                }
            }
        }

        // If the token is missing, proceed with the filter chain
        if (!StringUtils.hasText(token)) {
            filterChain.doFilter(request, response);
            return;
        }

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

            // Extract the list of authorities from the JWT token
            List<GrantedAuthority> authorities = ((List<?>) claims.get("roles")).stream()
                    .map(authority -> new SimpleGrantedAuthority((String) ((LinkedHashMap) authority).get("authority")))
                    .collect(Collectors.toList());

            // Authenticate the user with the extracted username and authorities
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e) {
            // Handle JWT validation errors
            logger.error("Error validating JWT token: {}");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }
}