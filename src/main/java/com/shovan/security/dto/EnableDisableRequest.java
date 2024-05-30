package com.shovan.security.dto;

import lombok.Data;

@Data
public class EnableDisableRequest {
    private String email;
    private boolean enabled;
}
