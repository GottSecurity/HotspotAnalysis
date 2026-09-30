package com.example;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class UserController {
    private final JdbcTemplate jdbc;

    public UserController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/users/{userId}")
    public String getUser(@PathVariable String userId, @RequestParam String accountId) {
        return jdbc.query("SELECT * FROM users WHERE id = '" + userId + "'");
    }

    @PostMapping("/users")
    public void save(@RequestBody User user) {
        userRepository.save(user);
    }

    @PostMapping("/upload")
    public void upload(MultipartFile file) throws Exception {
        file.transferTo(new java.io.File(file.getOriginalFilename()));
    }
}
