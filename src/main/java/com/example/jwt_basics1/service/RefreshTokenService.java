package com.example.jwt_basics1.service;

import com.example.jwt_basics1.config.JwtUtil;
import com.example.jwt_basics1.dto.AuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthenticationResponse refreshAccessToken(String refreshToken, HttpServletRequest request) {

        // check if the refresh token is blacklisted
        if (tokenBlacklistService.isTokenBlacklisted(refreshToken)) { // fix it to check the parent **ACCESS** token is blacklisted
            throw new RuntimeException("Refresh token is blacklisted");
        }

        // load the user details from the refresh token
        String username = jwtUtil.extractUsername(refreshToken);
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

//        String tokenIP = jwtUtil.extractClaim(refreshToken, claims -> claims.get("ip", String.class));
//        String requestIP = request.getRemoteAddr();
//        if (!requestIP.equals(tokenIP)) {
//            throw new RuntimeException("Invalid IP address for this refresh token");
//        }

        // check if the refresh token is valid
        if (!jwtUtil.validateToken(refreshToken, userDetails)) {
            throw new RuntimeException("Invalid or expired refresh token");
        }

        // create a new access token
        String newAccessToken = jwtUtil.generateToken(null, userDetails);

        // returns the new access token along with the refresh token
        return new AuthenticationResponse(newAccessToken, refreshToken);
    }
}
