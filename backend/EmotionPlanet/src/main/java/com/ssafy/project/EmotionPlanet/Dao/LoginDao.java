package com.ssafy.project.EmotionPlanet.Dao;

import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface LoginDao {
    public UserDto login(String email);
}
