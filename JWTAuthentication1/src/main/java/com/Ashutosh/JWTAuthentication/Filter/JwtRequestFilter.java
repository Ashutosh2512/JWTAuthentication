package com.Ashutosh.JWTAuthentication.Filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.Ashutosh.JWTAuthentication.Service.MyUserDetailsService;
import com.Ashutosh.JWTAuthentication.util.Jwt;

@Component
public class JwtRequestFilter extends OncePerRequestFilter{

	private MyUserDetailsService userDetailsService;
	
	private Jwt jwtUtil;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String AuthorizationHeader=request.getHeader("Authorization");
		String username=null;
		String jwt=null;
		
		if(AuthorizationHeader!=null && AuthorizationHeader.startsWith("Bearer ")) {
			jwt=AuthorizationHeader.substring(7);
			username=jwtUtil.extractUserName(jwt);
		}
		
		if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails=this.userDetailsService.loadUserByUsername(username);
			if(jwtUtil.validateToken(jwt, userDetails)) {
				UsernamePasswordAuthenticationToken usernamepasswordauthenticationtoken=new UsernamePasswordAuthenticationToken(userDetails, null,userDetails.getAuthorities());
				usernamepasswordauthenticationtoken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamepasswordauthenticationtoken);
			}
		}
		filterChain.doFilter(request,response);
	}

}
