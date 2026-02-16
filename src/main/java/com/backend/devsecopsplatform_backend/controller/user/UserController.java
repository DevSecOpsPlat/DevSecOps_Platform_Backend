package com.backend.devsecopsplatform_backend.controller.user;

import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.service.user.IUserService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {
    IUserService userService;

    @Autowired
    public UserController(IUserService userService){
        this.userService = userService;
    }

    @Operation(description = "Find All Users")
    @GetMapping("/users")
    public List<User> findUsers() {
        return userService.findUsers();
    }

    @Operation(description = "Find User By ID")
    @GetMapping("/{userId}")
    public User retrieveUser(@PathVariable("userId") long userId) {
        return userService.findUserById(userId);
    }

    @Operation(description = "Add User")
    @PostMapping("/add")
    public User addUser(@RequestBody User user){
        return userService.addUser(user);
    }

    @Operation(description = "Remove User")
    @DeleteMapping("/remove/{userId}")
    public void removeUser(@PathVariable("userId") long userId) {
        userService.removeUser(userId);
    }

    @Operation(description = "Update User")
    @PutMapping("/update")
    public User updateuser(@RequestBody User user) {
        return userService.updateUser(user);
    }
}
