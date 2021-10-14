package com.tingyu.security.dao;

import com.tingyu.security.entity.User;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDao {

    User loadUserByUsername(@Param("username") String username);

}
