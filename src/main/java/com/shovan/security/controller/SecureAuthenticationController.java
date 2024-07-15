package com.shovan.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.shovan.security.dto.AuthenticationResponse;
import com.shovan.security.dto.PasswordResetRequest;
import com.shovan.security.error.ApiException;
import com.shovan.security.service.AuthenticationService;
import com.shovan.security.service.JwtService;
import com.shovan.security.service.TokenService;
import com.shovan.security.util.ApiResponse;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/secure/auth")
@RequiredArgsConstructor
public class SecureAuthenticationController {

    private final AuthenticationService authenticationService;

    private final TokenService tokenService;

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@RequestHeader("Authorization") String authorizationHeader,
            @RequestBody PasswordResetRequest request) {
        try {
            String email = tokenService.extractEmail(authorizationHeader);

            if (!email.equals(request.getEmail())) {
                return new ResponseEntity<>(new ApiResponse<>(HttpStatus.UNAUTHORIZED, "Invalid Email", null),
                        HttpStatus.UNAUTHORIZED);
            }

            // authenticationService.resetPassword(request);
            ApiResponse<Void> response = new ApiResponse<>(HttpStatus.OK, "Password reset successfully", null);
            return ResponseEntity.ok(response);
        } catch (ApiException e) {
            return new ResponseEntity<>(new ApiResponse<>(e.getStatus(), e.getMessage(), null), e.getStatus());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String authorizationHeader) {
        try {
            String email = tokenService.extractEmail(authorizationHeader);
            authenticationService.logout(email);
            ApiResponse<Void> response = new ApiResponse<>(HttpStatus.OK, "Logged out successfully", null);
            return ResponseEntity.ok(response);
        } catch (ApiException e) {
            return new ResponseEntity<>(new ApiResponse<>(e.getStatus(), e.getMessage(), null), e.getStatus());
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<AuthenticationResponse>> refreshToken(
            @RequestHeader("Authorization") String authorizationHeader) {
        try {
            String email = tokenService.extractEmail(authorizationHeader);
            AuthenticationResponse response = authenticationService.refreshToken(email);
            ApiResponse<AuthenticationResponse> apiResponse = new ApiResponse<>(HttpStatus.OK,
                    "Token refreshed successfully", response);
            return ResponseEntity.ok(apiResponse);
        } catch (ApiException e) {
            return new ResponseEntity<>(new ApiResponse<>(e.getStatus(), e.getMessage(), null), e.getStatus());
        }
    }
}