package com.shovan.security.service;

import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OtpService {

    // @Value("${app.otp.expiration-time}")
    private long OTP_EXPIRATION_TIME = 5;

    private final RedisTemplate<String, Object> redisTemplate;
    private final String OTP_PREFIX = "OTP:";
    private final Random random = new Random();

    public void generateAndSendOtp(String email) {

        try {
            String otp = String.format("%06d", random.nextInt(999999));
            redisTemplate.opsForValue().set(OTP_PREFIX + email, otp, OTP_EXPIRATION_TIME, TimeUnit.MINUTES);
            System.out.println("otp: " + otp);
            // TODO: Implement the logic to send the OTP to the user's email
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
            throw new RuntimeException("Failed to generate and send OTP");
        }
    }

    // Verify OTP entered by the user
    public boolean verifyOtp(String email, String otp) {

        try {
            System.out.println("email: " + email);
            System.out.println("otp: " + otp);

            String storedOtp = (String) redisTemplate.opsForValue().get(OTP_PREFIX + email);
            System.out.println("storedOtp: " + storedOtp);
            boolean isValid = otp != null && otp.equals(storedOtp);

            if (isValid) {
                redisTemplate.delete(OTP_PREFIX + email);
            }
            return isValid;
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
            return false;
        }
    }

}
