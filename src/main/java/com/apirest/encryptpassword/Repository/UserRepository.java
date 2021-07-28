package com.apirest.encryptpassword.Repository;

import com.apirest.encryptpassword.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    public Optional<User> findByLogin(String login);
}
