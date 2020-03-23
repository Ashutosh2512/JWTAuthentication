package com.Ashutosh.JWTAuthentication.util;

import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class Jwt {
	private String SECRET_KEY="I AM THE SECRET KEY";
	
	public String extractUserName(String token) {
		return extractClaim(token,Claims::getSubject);
	}
	public Date extractExpirationTime(String token) {
		return extractClaim(token,Claims::getExpiration);
	}
	public Boolean isTokenExpired(String token) {
		return extractExpirationTime(token).before(new Date());
	}
	
	public <T> T extractClaim(String token,Function<Claims,T> claimsResolver){
		final Claims claims=extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	public Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
	}
	public String generateToken(UserDetails userdetails) {
		HashMap<String,Object> claims=new HashMap<>();
		return createToken(claims,userdetails.getUsername());
	}

	public String createToken(HashMap<String,Object> claims,String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+1000*60*60*10)).signWith(SignatureAlgorithm.HS256,SECRET_KEY).compact();
	}
	public Boolean validateToken(String token,UserDetails userdetails) {
		String userName=extractUserName(token);
		if(userName.equals(userdetails.getUsername()) && !isTokenExpired(token)) {
			return  true;
		}
		return false;
	}
}
