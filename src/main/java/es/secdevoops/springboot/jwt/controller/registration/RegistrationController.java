package es.secdevoops.springboot.jwt.controller.registration;

import es.secdevoops.springboot.jwt.dto.AuthenticationResponse;
import es.secdevoops.springboot.jwt.dto.RegisterRequest;
import es.secdevoops.springboot.jwt.service.auth.AuthenticationService;
import es.secdevoops.springboot.jwt.service.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/secdevoops/register")
@RequiredArgsConstructor
public class RegistrationController {

    private final UserService service;

    @PostMapping("/user")
    public ResponseEntity<AuthenticationResponse> registerUser(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(service.registerUser(request));
    }

    @PostMapping("/admin")
    public ResponseEntity<AuthenticationResponse> registerAdmin(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(service.registerAdmin(request));
    }

}
