package com.example.jwt_basics1.service;

import com.example.jwt_basics1.config.JwtUtil;
import com.example.jwt_basics1.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;

    public AuthenticationResponse refreshAccessToken(String refreshToken) {
        // load the user details from the refresh token
        String username = jwtUtil.extractUsername(refreshToken);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

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
