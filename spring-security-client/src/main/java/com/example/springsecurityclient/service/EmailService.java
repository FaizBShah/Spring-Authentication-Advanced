package com.example.springsecurityclient.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EmailService {
    public void sendVerificationTokenEmail(String tokenUrl, String email) {
        log.info("Click the link to verify your account for email {}: {}", email, tokenUrl);
    }
}
