package com.ssafy.project.EmotionPlanet.Controller;

import javax.servlet.http.HttpSession;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;


@CrossOrigin(
        origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"},
        allowCredentials = "true",
        allowedHeaders = "*",
        methods = { RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                RequestMethod.DELETE, RequestMethod.HEAD, RequestMethod.OPTIONS })

@RestController // 값자체를 리턴
public class LogoutController {

    @PostMapping(value = "/logout")  // post 방식으로 들어옴
    public ResponseEntity<String> logout(@RequestBody UserDto dto, HttpSession session) {
    	// 여기 이제 로그아웃 구현하는데 dto에 회원 번호 넘어올거니깐 뭐 그거 가지고 사용해야할듯 서비스 부분도 만들어야 할수도.
    	//        if (userDto != null) {
//            session.setAttribute("userDto", userDto);
//            return new ResponseEntity<UserDto>(userDto, HttpStatus.OK);
//        } else {
//            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "이메일 혹은 비밀번호가 잘못되었습니다.");
//        }
    	return null;
    }
}
