package es.secdevoops.springboot.jwt.service.auth;

import es.secdevoops.springboot.jwt.dto.AuthenticationRequest;
import es.secdevoops.springboot.jwt.repository.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserAccountRepository userAccountRepository;

    public String authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userAccountRepository.findByUsername(request.getEmail());
        return jwtService.generateToken(user.orElseThrow());
    }

}