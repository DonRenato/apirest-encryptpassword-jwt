package com.apirest.encryptpassword.controller;

import com.apirest.encryptpassword.Repository.UserRepository;
import com.apirest.encryptpassword.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(value = "/api")
public class UserController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping(value = "/users")
    public ResponseEntity<List<User>> listAll(){
        return ResponseEntity.ok(userRepository.findAll());
    }

    @PostMapping(value = "/user")
    public ResponseEntity<User> saveUser(@RequestBody User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return ResponseEntity.ok(userRepository.save(user));
    }
    @GetMapping(value = "/user/validate")
    public ResponseEntity<Boolean> validatePassword(@RequestParam String login, @RequestParam String password){


        Optional<User> userOpt = userRepository.findByLogin(login);
        if(!userOpt.isPresent()){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
        }

        User user = userOpt.get();
        boolean valid = passwordEncoder.matches(password, user.getPassword());

        HttpStatus status = valid ? HttpStatus.OK : HttpStatus.UNAUTHORIZED;

        return ResponseEntity.status(status).body(valid);
    }
}
