package com.shovan.security.dto;

import lombok.Data;

@Data
public class PasswordResetRequest {
    private String email;
    private String newPassword;
}