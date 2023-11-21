package com.gopang.authorizationserver.repository;

import com.gopang.authorizationserver.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {
    User findByEmail(String email); // 이메일을 통해 사용자 정보를 가져옴
}
