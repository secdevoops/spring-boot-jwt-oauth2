package es.secdevoops.springboot.jwt.security;

import es.secdevoops.springboot.jwt.entities.CustomOAuth2User;
import es.secdevoops.springboot.jwt.entities.Provider;
import es.secdevoops.springboot.jwt.entities.Role;
import es.secdevoops.springboot.jwt.entities.UserAccount;
import es.secdevoops.springboot.jwt.service.auth.JwtService;
import es.secdevoops.springboot.jwt.service.user.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;

    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication)
            throws IOException, ServletException {
        AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
        AtomicReference<UserAccount> userAccount = new AtomicReference<>();
        userService.findUser(oauthUser.getEmail()).ifPresentOrElse((user -> {
            userAccount.set(user);
        }), () -> {
            //Otherwise, create the user
            userAccount.set(userService.createUser(oauthUser.getEmail(), "", oauthUser.getName(), Role.USER_ROLE, Provider.GOOGLE));
        });

        String token = jwtService.generateToken(userAccount.get());
        Cookie jwtCookie = new Cookie("secdevoops-token", token);
        jwtCookie.setHttpOnly(true); // Protege la cookie contra ataques de scripting en el lado del cliente
        //jwtCookie.setSecure(true); // Asegura que la cookie solo se envíe a través de HTTPS
        jwtCookie.setMaxAge(Long.valueOf(jwtService.getExpirationTime()/1000).intValue()); // Configura la cookie para que expire después del tiempo preestablecido (en segs)
        jwtCookie.setPath("/"); // Permite que la cookie sea accesible en todo el sitio

        //Añadimos el jwt token tanto en la cabecera Authorization como en una cookie segura, para que se pueda usar según se necesite
        response.addCookie(jwtCookie);
        response.setHeader("Authorization", "Bearer "+ token);
        response.sendRedirect("/secdevoops/hello");
    }
}
