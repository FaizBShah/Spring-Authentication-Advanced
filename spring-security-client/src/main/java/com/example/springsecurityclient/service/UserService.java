package com.example.springsecurityclient.service;

import com.example.springsecurityclient.entity.User;
import com.example.springsecurityclient.model.UserModel;

public interface UserService {

    User registerUser(UserModel userModel);

    String validateVerificationToken(String token);

    void resendVerificationToken(String email, String applicationUrl);

    User findUserByEmail(String email);

    void sendResetPasswordToken(String email, String applicationUrl);

    String validateResetPasswordToken(String token);

    void resetPassword(String email, String password);

}
