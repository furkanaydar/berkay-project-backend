package com.project.demo.controller;

import com.project.demo.dto.LoginCredentials;
import com.project.demo.dto.RegisterCredentialsCorporate;
import com.project.demo.model.Corporate;
import com.project.demo.model.User;
import com.project.demo.repository.CorporateRepository;
import com.project.demo.repository.WorkerRepository;
import com.project.demo.security.JwtTokenProvider;
import com.project.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;


    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    private CorporateRepository corporateRepository;

    @Autowired
    private WorkerRepository workerRepository;

    public AuthenticationController(AuthenticationManager authenticationManager, UserService userService, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/corporateLogin")
    public ResponseEntity<?> login(@RequestBody LoginCredentials data) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(data.getUsername(), data.getPassword());

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwtToken = jwtTokenProvider.generateJwtToken(authentication);


        String username = "";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            username = ((UserDetails)principal).getUsername();
        } else {
            username = principal.toString();
        }
        User loggedInUser = userService.findUserByUsername(username);
        Map<String, Object> body = new HashMap<>();
        body.put("Authorization", "Bearer " + jwtToken);
        body.put("Corporate", corporateRepository.findCorporateByCorporateEmail(loggedInUser.getEmail()));
        return new ResponseEntity<Object>(body, HttpStatus.OK);
    }

    @PostMapping("/workerLogin")
    public ResponseEntity<Object> loginWorker(@RequestBody LoginCredentials data) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(data.getUsername(), data.getPassword());

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwtToken = jwtTokenProvider.generateJwtToken(authentication);


        String username = "";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            username = ((UserDetails)principal).getUsername();
        } else {
            username = principal.toString();
        }
        User loggedInUser = userService.findUserByUsername(username);
        Map<String, Object> body = new HashMap<>();
        body.put("Authorization", "Bearer " + jwtToken);
        body.put("Worker", workerRepository.findWorkerByWorkerUsername(username));
        return new ResponseEntity<Object>(body, HttpStatus.OK);
    }

    @PostMapping("/corporateRegister")
    public ResponseEntity<?> register(@RequestBody RegisterCredentialsCorporate data) {
        if (null != userService.findUserByUsername(data.getUsername())) {
            return new ResponseEntity<>("Username already in use.", HttpStatus.BAD_REQUEST);
        } else if (null != userService.findUserByEmail(data.getEmail())) {
            return new ResponseEntity<>("Email already in use.", HttpStatus.BAD_REQUEST);
        }

        User user = new User(data.getUsername(), passwordEncoder.encode(data.getPassword()), data.getEmail());
        if (data.getUserRole() == null) {
            user.setUserRole("none");
        } else {
            user.setUserRole(data.getUserRole());
        }
        Corporate corporate = new Corporate(data.getCorporateName(), passwordEncoder.encode(data.getPassword()), data.getEmail());
        corporateRepository.save(corporate);
        userService.saveUser(user);
        return new ResponseEntity<>("User successfully registered.", HttpStatus.OK);
    }

}
