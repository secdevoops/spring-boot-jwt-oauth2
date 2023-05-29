package es.secdevoops.springboot.jwt.controller.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
class LoginController {

    @GetMapping("/login")
    String login() {
        return "login";
    }

}