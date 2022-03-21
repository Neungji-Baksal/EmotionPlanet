package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dao.FeedDao;
import com.ssafy.project.EmotionPlanet.Dao.LoginDao;
import com.ssafy.project.EmotionPlanet.Dto.FeedDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LoginServiceImpl implements LoginService {
    @Autowired
    LoginDao loginDao;

    @Autowired
    FeedDao feedDao;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDto login(UserDto dto) { // 로그인 처리
        UserDto userDto = loginDao.login(dto.getEmail());
        if(userDto != null && passwordEncoder.matches(dto.getPw(), userDto.getPw())) { //이메일에 대한 회원 정보가 존재하고 비밀번호가 같으면 로그인 성공
            List<FeedDto> feedDtos = feedDao.myList(userDto.getNo());
            if(feedDtos == null) userDto.setFeedCount(0);
            else userDto.setFeedCount(feedDtos.size());
            return userDto;
        }else {
            return null;
        }
    }

}
