package com.Ashutosh.JWTAuthentication.model;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;

public class AuthenticationResponse {

	private final String jwt;
	
	public AuthenticationResponse(String jwt) {
		this.jwt=jwt;
	}
	
	public String getJwt() {
		return this.jwt;
	}
	
	
}
