package es.secdevoops.springboot.jwt.service.user;

import es.secdevoops.springboot.jwt.dto.AuthenticationResponse;
import es.secdevoops.springboot.jwt.dto.RegisterRequest;
import es.secdevoops.springboot.jwt.entities.Provider;
import es.secdevoops.springboot.jwt.entities.Role;
import es.secdevoops.springboot.jwt.entities.UserAccount;
import es.secdevoops.springboot.jwt.repository.RoleRepository;
import es.secdevoops.springboot.jwt.repository.UserAccountRepository;
import es.secdevoops.springboot.jwt.service.auth.JwtService;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserAccountRepository userAccountRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthenticationResponse registerUser(RegisterRequest request) {
        return registerUserWithRole(Role.USER_ROLE, request);
    }
    public AuthenticationResponse registerAdmin(RegisterRequest request) {
        return registerUserWithRole(Role.ADMIN_ROLE, request);
    }

    private AuthenticationResponse registerUserWithRole(String userRole, RegisterRequest request) {
        var user = createUser(request.getEmail(), request.getPassword(), request.getName(), userRole, Provider.LOCAL);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public UserAccount createUser(String username, String password, String name, String userRole, Provider provider) {
        Role role = roleRepository.findByRolename(userRole).orElseThrow();
        var user = new UserAccount(username, passwordEncoder.encode(password), name);
        user.setRoles(List.of(role));
        user.setProvider(provider);
        return userAccountRepository.save(user);
    }

    public Optional<UserAccount> findUser(String username){
        return userAccountRepository.findByUsername(username);
    }

}
