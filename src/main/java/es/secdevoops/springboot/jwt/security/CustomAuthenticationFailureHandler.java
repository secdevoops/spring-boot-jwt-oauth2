package es.secdevoops.springboot.jwt.security;

import es.secdevoops.springboot.jwt.entities.CustomOAuth2User;
import es.secdevoops.springboot.jwt.entities.Provider;
import es.secdevoops.springboot.jwt.entities.Role;
import es.secdevoops.springboot.jwt.entities.UserAccount;
import es.secdevoops.springboot.jwt.repository.RoleRepository;
import es.secdevoops.springboot.jwt.repository.UserAccountRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final UserAccountRepository userAccountRepository;
    private final RoleRepository roleRepository;


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {
        log.error("Error: ", exception);
    }
}
