package io.aviraj.spring.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

	@GetMapping("/")
	public String getDefaultSecurityPage() {
		return "Welcome to the Security Page";
	}
	
	@GetMapping("/user")
	public String getUserPage() {
		return "Welcome to the User Page";
	}
	
	@GetMapping("/admin")
	public String getAdminPage() {
		return "Welcome to the Admin Page";
	}
	
}
