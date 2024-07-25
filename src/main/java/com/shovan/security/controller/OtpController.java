package com.shovan.security.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.shovan.security.error.ApiException;
import com.shovan.security.service.OtpService;
import com.shovan.security.util.ApiResponse;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth/")
@RequiredArgsConstructor
public class OtpController {

    private final OtpService otpService;

    @PostMapping("/send-otp")
    public ResponseEntity<ApiResponse<Void>> requestOtp(@RequestBody Map<String, String> requestBody) {

        try {

            String email = requestBody.get("email");
            otpService.generateAndSendOtp(email);

            ApiResponse<Void> apiResponse = new ApiResponse<>(HttpStatus.OK, "OTP send successfully", null);

            return ResponseEntity.ok(apiResponse);
        } catch (ApiException e) {
            e.printStackTrace();
            ApiResponse<Void> apiResponse = new ApiResponse<>(e.getStatus(), e.getMessage(), null);
            return new ResponseEntity<>(apiResponse, e.getStatus());
        }
    }
}
