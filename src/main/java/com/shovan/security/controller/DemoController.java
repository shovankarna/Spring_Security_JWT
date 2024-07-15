package com.shovan.security.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.shovan.security.error.ApiException;
import com.shovan.security.util.ApiResponse;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/api/v1/demo")
@RequiredArgsConstructor
public class DemoController {

    @GetMapping("/hello")
    public ResponseEntity<ApiResponse<String>> sayHello() {
        try {
            ApiResponse<String> response = new ApiResponse<>(HttpStatus.OK, "Request successful",
                    "Hello from secured Endpoint");
            return ResponseEntity.ok(response);
        } catch (ApiException e) {
            System.out.println(e.getStatus() + e.getMessage());
            return new ResponseEntity<>(new ApiResponse<>(e.getStatus(), e.getMessage(), null), e.getStatus());
        }
    }

}
