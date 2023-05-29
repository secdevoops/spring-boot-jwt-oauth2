package es.secdevoops.springboot.jwt.controller;

import es.secdevoops.springboot.jwt.service.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class HelloWorldController {

	@Autowired
	private final UserService userService;

	@GetMapping(value="/secdevoops/hello")
	public String hello() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		var user = userService.findUser(authentication.getPrincipal().toString());
		return String.format("Hello %s!!!!", user.get().getName());
	}



}