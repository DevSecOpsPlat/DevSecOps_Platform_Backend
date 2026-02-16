package com.backend.devsecopsplatform_backend.service.user;

import com.backend.devsecopsplatform_backend.entity.User;

import java.util.List;

public interface IUserService {

    public List<User> findUsers();
    public User findUserById(Long id);
    public User addUser(User user);
    public User updateUser(User user);
    public void removeUser(Long id);

}
