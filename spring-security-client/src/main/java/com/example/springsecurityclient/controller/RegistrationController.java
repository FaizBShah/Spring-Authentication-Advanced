package com.example.springsecurityclient.controller;

import com.example.springsecurityclient.entity.User;
import com.example.springsecurityclient.event.RegistrationCompleteEvent;
import com.example.springsecurityclient.model.ResetPasswordModel;
import com.example.springsecurityclient.model.SavePasswordModel;
import com.example.springsecurityclient.model.UserModel;
import com.example.springsecurityclient.service.HttpRequestService;
import com.example.springsecurityclient.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
public class RegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private HttpRequestService httpRequestService;

    @Autowired
    private ApplicationEventPublisher publisher;

    @PostMapping("/register")
    public String registerUser(@RequestBody UserModel userModel, final HttpServletRequest request) {
        User user = userService.registerUser(userModel);
        publisher.publishEvent(new RegistrationCompleteEvent(
                user,
                httpRequestService.applicationUrl(request)
        ));

        return "Success";
    }

    @GetMapping("/verifyRegistration")
    public String verifyRegistration(@RequestParam("token") String token) {
        String result = userService.validateVerificationToken(token);
        return result.equalsIgnoreCase("valid") ? "User verified successfully" : result;
    }

    @PostMapping("/resendVerificationToken")
    public String resendVerificationToken(@RequestParam("email") String email, HttpServletRequest request) {
        userService.resendVerificationToken(email, httpRequestService.applicationUrl(request));
        return "Verification Token Resent";
    }

    @PostMapping("/resetPassword")
    public String resetPassword(@RequestBody ResetPasswordModel passwordModel, HttpServletRequest request) {
        userService.sendResetPasswordToken(passwordModel.getEmail(), httpRequestService.applicationUrl(request));
        return "Reset Password Token Sent";
    }

    @PostMapping("/savePassword")
    public String savePassword(@RequestParam("token") String token, @RequestBody SavePasswordModel passwordModel) {
        String result = userService.validateResetPasswordToken(token);

        if (!result.equalsIgnoreCase("valid")) {
            return result;
        }

        userService.resetPassword(passwordModel.getEmail(), passwordModel.getPassword());

        return "Password has been reset";
    }
}
