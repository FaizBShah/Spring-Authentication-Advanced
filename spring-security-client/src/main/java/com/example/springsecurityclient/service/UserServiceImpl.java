package com.example.springsecurityclient.service;

import com.example.springsecurityclient.entity.ResetPasswordToken;
import com.example.springsecurityclient.entity.User;
import com.example.springsecurityclient.entity.VerificationToken;
import com.example.springsecurityclient.model.UserModel;
import com.example.springsecurityclient.repository.ResetPasswordTokenRepository;
import com.example.springsecurityclient.repository.UserRepository;
import com.example.springsecurityclient.repository.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private ResetPasswordTokenRepository resetPasswordTokenRepository;

    @Autowired
    private VerificationTokenService verificationTokenService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public User registerUser(UserModel userModel) {
        User user = User.builder()
                .firstName(userModel.getFirstName())
                .lastName(userModel.getLastName())
                .email(userModel.getEmail())
                .role("USER")
                .password(passwordEncoder.encode(userModel.getPassword()))
                .build();

        return userRepository.save(user);
    }

    @Override
    public String validateVerificationToken(String token) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token);

        if (verificationToken == null) {
            return "Invalid";
        }

        if (verificationToken.getExpirationTime().getTime() - Calendar.getInstance().getTime().getTime() <= 0) {
            verificationTokenRepository.delete(verificationToken);
            return "Token expired";
        }

        User user = verificationToken.getUser();

        if (user.isEnabled()) {
            verificationTokenRepository.delete(verificationToken);
            return "User already verified";
        }

        user.setEnabled(true);

        userRepository.save(user);

        return "valid";
    }

    @Override
    @Transactional
    public void resendVerificationToken(String email, String applicationUrl) {
        User user = userRepository.findByEmail(email);
        VerificationToken verificationToken = verificationTokenRepository.findByUserId(user.getId());

        verificationTokenRepository.delete(verificationToken);

        String token = UUID.randomUUID().toString();

        verificationTokenService.saveVerificationTokenForUser(user, token);

        String url = applicationUrl + "/verifyRegistration?token=" + token;

        emailService.sendVerificationTokenEmail(url, email);
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public void sendResetPasswordToken(String email, String applicationUrl) {
        User user = userRepository.findByEmail(email);

        if (user == null) {
            return;
        }

        String token = UUID.randomUUID().toString();

        ResetPasswordToken resetPasswordToken = new ResetPasswordToken(user, token);
        resetPasswordTokenRepository.save(resetPasswordToken);

        String url = applicationUrl + "/savePassword?token=" + token;

        emailService.sendVerificationTokenEmail(url, email);
    }

    @Override
    public String validateResetPasswordToken(String token) {
        ResetPasswordToken resetPasswordToken = resetPasswordTokenRepository.findByToken(token);

        if (resetPasswordToken == null) {
            return "Invalid";
        }

        if (resetPasswordToken.getExpirationTime().getTime() - Calendar.getInstance().getTime().getTime() <= 0) {
            resetPasswordTokenRepository.delete(resetPasswordToken);
            return "Token expired";
        }

        return "valid";
    }

    @Override
    public void resetPassword(String email, String password) {
        User user = userRepository.findByEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }
}
