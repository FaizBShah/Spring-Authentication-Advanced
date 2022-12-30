package com.example.springsecurityclient.model;

import lombok.Data;

@Data
public class SavePasswordModel {
    private final String email;
    private final String password;
}
