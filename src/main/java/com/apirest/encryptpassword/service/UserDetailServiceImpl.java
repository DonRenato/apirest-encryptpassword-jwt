package com.apirest.encryptpassword.service;

import com.apirest.encryptpassword.Repository.UserRepository;
import com.apirest.encryptpassword.data.UserDetailData;
import com.apirest.encryptpassword.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class UserDetailServiceImpl implements UserDetailsService {

   @Autowired
    private UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String user) throws UsernameNotFoundException {
       Optional<User> username = userRepository.findByLogin(user);

       if(!username.isPresent()){
           throw new UsernameNotFoundException("User ["+ username + "] not found");
       }

       return new UserDetailData(username);
    }
}
