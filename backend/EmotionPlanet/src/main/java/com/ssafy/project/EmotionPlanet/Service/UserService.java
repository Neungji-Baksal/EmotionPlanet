package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dto.FindEmailDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import com.ssafy.project.EmotionPlanet.Dto.UserSecretDto;

public interface UserService {
    public int userRegister(UserDto dto);
    public UserDto userSelect(int no);
    public UserDto userSelectByEmail(String email);
    public int userDelete(int no);
    public int duplicateEmail(String email);
    public int duplicateNickname(String nickname);
    public int userUpdate(UserDto userDto, UserDto changuserDto);
    public int duplicateTel(String tel);
    public String findEamil(String tel);
    public String findPw(FindEmailDto findEmailDto);
    public int userRefreshToken(UserDto userDto);
    public String selectRefreshToken(String email);
}