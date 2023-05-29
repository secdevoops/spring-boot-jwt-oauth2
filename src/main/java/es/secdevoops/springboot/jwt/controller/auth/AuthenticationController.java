package es.secdevoops.springboot.jwt.controller.auth;


import es.secdevoops.springboot.jwt.dto.AuthenticationRequest;
import es.secdevoops.springboot.jwt.dto.AuthenticationResponse;
import es.secdevoops.springboot.jwt.service.auth.AuthenticationService;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/secdevoops/auth")
public class AuthenticationController {

    @Autowired
    @Value("${spring.security.jwt.expiration-time}")
    private final Long expirationTime;
    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(@Value("${spring.security.jwt.expiration-time}") Long expirationTime,
            AuthenticationService authenticationService) {
        this.expirationTime = expirationTime;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        try {
            String token = authenticationService.authenticate(request);

            HttpHeaders headers = new HttpHeaders();
            //Añadimos el jwt token tanto en la cabecera Authorization como en una cookie segura, para que se pueda usar según se necesite
            headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
            headers.add(HttpHeaders.SET_COOKIE,
                    ResponseCookie.from("secdevoops-token", token)
                            .httpOnly(true) // Protege la cookie contra ataques de scripting en el lado del cliente
                            //.secure(true) // Asegura que la cookie solo se envíe a través de HTTPS
                            .maxAge(expirationTime/1000) // Configura la cookie para que expire según lo establecido (en segs)
                            .path("/") // Permite que la cookie sea accesible en todo el sitio
                            .build()
                            .toString());
            headers.add(HttpHeaders.LOCATION, "/secdevoops/hello");
            return ResponseEntity.ok().headers(headers).build();
        }catch (AuthenticationException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }
}
