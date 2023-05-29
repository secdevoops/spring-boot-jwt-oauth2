package es.secdevoops.springboot.jwt.controller.auth;


import es.secdevoops.springboot.jwt.dto.AuthenticationRequest;
import es.secdevoops.springboot.jwt.dto.AuthenticationResponse;
import es.secdevoops.springboot.jwt.service.auth.AuthenticationService;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        try {
            String token = service.authenticate(request);

            HttpHeaders headers = new HttpHeaders();
            //Añadimos el jwt token tanto en la cabecera Authorization como en una cookie segura, para que se pueda usar según se necesite
            headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
            headers.add(HttpHeaders.SET_COOKIE,
                    ResponseCookie.from("secdevoops-token", token)
                            .httpOnly(true) // Protege la cookie contra ataques de scripting en el lado del cliente
                            //.secure(true) // Asegura que la cookie solo se envíe a través de HTTPS
                            .maxAge(7 * 24 * 60 * 60) // Configura la cookie para que expire después de 7 días
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
