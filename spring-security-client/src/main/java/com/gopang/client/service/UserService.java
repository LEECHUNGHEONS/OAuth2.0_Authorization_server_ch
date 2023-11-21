package com.gopang.client.service;


import com.gopang.client.entity.User;
import com.gopang.client.entity.VerificationToken;
import com.gopang.client.model.UserModel;

import java.util.Optional;


//@Component
public interface UserService {
    User registerUser(UserModel userModel);

    void saveVerificationTokenForUser(String token, User user);

    String validateVerificationToken(String token);

    VerificationToken generateNewVerificationToken(String oldToken);

    User findUserByEmail(String email);

    void createPasswordResetTokenForUser(User user, String token);

    String validatePasswordResetToken(String token);

    Optional<User> getUserByPasswordResetToken(String token);

    void changePassword(User user, String newPasword);

    boolean checkIfValidOldPass(User user, String oldPassword);
}
