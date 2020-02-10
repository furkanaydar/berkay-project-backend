package com.project.demo.service;

import com.project.demo.model.User;

import java.util.List;

public interface UserService {
    User findUserById(Long id);
    User findUserByUsername(String username);
    User findUserByEmail(String email);
    List<User> findAll();
    User saveUser(User user);
}