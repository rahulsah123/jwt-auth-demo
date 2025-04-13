package com.example.jwtauthdemo.controller;

import com.example.jwtauthdemo.model.request.AuthRequest;
import com.example.jwtauthdemo.model.response.AuthResponse;
import com.example.jwtauthdemo.utils.JwtUtil;
import com.example.jwtauthdemo.model.request.TokenRefreshRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        String accessToken = jwtUtil.generateToken(request.getUsername());
        String refreshToken = jwtUtil.generateRefreshToken(request.getUsername());

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refresh(@RequestBody TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();
        if (jwtUtil.isTokenValid(refreshToken)) {
            String username = jwtUtil.extractUsername(refreshToken);
            String newAccessToken = jwtUtil.generateToken(username);
            return ResponseEntity.ok(new AuthResponse(newAccessToken, refreshToken));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
    }
}