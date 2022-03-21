package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import org.springframework.stereotype.Service;

public interface LoginService {
    public UserDto login(UserDto dto);
}
