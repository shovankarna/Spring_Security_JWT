package com.shovan.security.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.shovan.security.dto.AuthenticationRequest;
import com.shovan.security.dto.AuthenticationResponse;
import com.shovan.security.dto.EnableDisableRequest;
import com.shovan.security.dto.PasswordResetRequest;
import com.shovan.security.dto.RegisterRequest;
import com.shovan.security.error.ApiException;
import com.shovan.security.service.AuthenticationService;
import com.shovan.security.util.ApiResponse;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@RequestMapping("/api/v1/auth/")
@RequiredArgsConstructor
public class AuthenticationController {

    @Value("${app.redirect-url}")
    private String redirectUrl;

    private final AuthenticationService authenticationService;

    @GetMapping("/register-page")
    public String showRegisterPage(Model model) {
        // model.addAttribute("redirectUrl", redirectUrl);
        return "register";
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthenticationResponse>> register(@RequestBody RegisterRequest request,
            HttpServletResponse response) {
        try {
            AuthenticationResponse authResponse = authenticationService.register(request);

            // Set the JWT token as a secure, HTTP-only cookie
            ResponseCookie jwtCookie = ResponseCookie.from("jwt", authResponse.getToken())
                    .httpOnly(true)
                    .secure(true) // set to true if using HTTPS
                    .path("/")
                    .maxAge(Duration.ofMinutes(30)) // or however long you want the token to be valid
                    .sameSite("Strict")
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());

            // Remove the token from the response object
            authResponse.setToken(null);

            ApiResponse<AuthenticationResponse> apiResponse = new ApiResponse<>(HttpStatus.OK,
                    "User registered successfully", authResponse);
            authResponse.setRedirectUrl(redirectUrl);
            System.out.println("apiResponse: " + apiResponse);
            return ResponseEntity.ok(apiResponse);

        } catch (ApiException e) {
            ApiResponse<AuthenticationResponse> apiResponse = new ApiResponse<>(e.getStatus(), e.getMessage(), null);
            return new ResponseEntity<>(apiResponse, e.getStatus());
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<ApiResponse<AuthenticationResponse>> authenticate(
            @RequestBody AuthenticationRequest request) {
        try {
            AuthenticationResponse response = authenticationService.authenticate(request);
            ApiResponse<AuthenticationResponse> apiResponse = new ApiResponse<>(HttpStatus.OK,
                    "User authenticated successfully", response);
            return ResponseEntity.ok(apiResponse);
        } catch (ApiException e) {
            return new ResponseEntity<>(new ApiResponse<>(e.getStatus(), e.getMessage(), null), e.getStatus());
        }
    }
}
