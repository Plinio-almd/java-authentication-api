package my.project.authentication_api.controller;

import my.project.authentication_api.model.User;
import my.project.authentication_api.repository.UserRepository;
import my.project.authentication_api.service.impl.MyUserService;
import my.project.authentication_api.webToken.JjwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JjwtService jjwtService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private MyUserService myUserDetailService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/auth")
    public String authenticateAndGetToken(@RequestBody User loginInfo){
        Authentication authentication = authenticationManager.authenticate( new UsernamePasswordAuthenticationToken(
                loginInfo.getUsername(), loginInfo.getPassword()
        ));
        if (authentication.isAuthenticated()){
            return jjwtService.generateToken(myUserDetailService.loadUserByUsername(loginInfo.getUsername()));
        } else {
            throw  new UsernameNotFoundException("Invalid credentials.");
        }
    }

    @PostMapping("/register")
    public User createUser(@RequestBody User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getName()==null){
            user.setName(user.getUsername());
        }
        return userRepository.save(user);
    }

    @GetMapping("/home/admin")
    public ResponseEntity<String> homePageAdmin(){
        return ResponseEntity.ok("Welcome to Admin Home Page!");
    }
    @GetMapping("/home/user")
    public ResponseEntity<String> homePage(){
        return ResponseEntity.ok("Welcome to Ordinary User Home Page!");
    }
}
