package com.ssafy.project.EmotionPlanet.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.websocket.Session;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.ssafy.project.EmotionPlanet.Config.JWT.JwtService;
import com.ssafy.project.EmotionPlanet.Config.OAuth.PrincipalOauth2UserService;
import com.ssafy.project.EmotionPlanet.Dto.ErrorDto;
import com.ssafy.project.EmotionPlanet.Dto.TokenDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import com.ssafy.project.EmotionPlanet.Dto.UserSecretDto;
import com.ssafy.project.EmotionPlanet.Service.LoginService;
import com.ssafy.project.EmotionPlanet.Service.UserService;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;


@CrossOrigin(
        origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"},
        allowCredentials = "true",
        allowedHeaders = "*",
        methods = { RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                RequestMethod.DELETE, RequestMethod.HEAD, RequestMethod.OPTIONS })

@RestController // 값자체를 리턴
public class LoginController {

    @Autowired
    PrincipalOauth2UserService principalOauth2UserService;

    @Autowired
    JwtService jwtService;

    @Autowired
    UserService userService;

    @Autowired
    LoginService loginService;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;


//    @PostMapping(value = "/login")  // post 방식으로 들어옴
//    public ResponseEntity<?> login(@RequestBody UserDto dto, HttpSession session) { // 로그인
//        UserDto userDto = loginService.login(dto);
//        HttpHeaders res = new HttpHeaders();
//        if (userDto != null) {
//        	System.out.println("로그인 성공");
//            System.out.println(userDto);
//        	session.setAttribute("userDto", userDto); // 세션에 회원 정보 저장.
//            return ResponseEntity.ok().headers(res).body(userDto);
//        } else {
//        	System.out.println("로그인 실패");
//            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "이메일 혹은 비밀번호가 잘못되었습니다.");
//        }
//    }

    @PostMapping(value = "/login")  // post 방식으로 들어옴
    public ResponseEntity<?> login(@RequestBody UserDto dto) { // 로그인

        System.out.println("로그인 접근완료");

        UserDto user = loginService.login(dto);
        UserSecretDto userDto = new UserSecretDto();
        if(user != null) userDto = new UserSecretDto(user.getNo(), user.getEmail(),
                user.getNickname(), user.getBirth(), user.getProfileImg(), user.getTel(), user.getIntro() ,
                user.getPublish(), user.getMood(), user.getFeedCount());

        HttpHeaders res = new HttpHeaders();
        if (user != null) {
        	System.out.println("로그인 성공");
            System.out.println(userDto);
            TokenDto atJWT = jwtService.create(userDto);
            System.out.println("로그인 컨트롤 atJWT");
            System.out.println(atJWT);
            res.add("at-jwt-access-token", atJWT.getAccessJws());
            res.add("at-jwt-refresh-token", atJWT.getRefreshJws());
            user.setRefreshToken(atJWT.getRefreshJws());
            userService.userRefreshToken(user);

            return ResponseEntity.ok().headers(res).body(user);
        } else {
        	System.out.println("로그인 실패");
            ErrorDto errorDto = new ErrorDto();
            errorDto.setMessage("이메일 혹은 비밀번호가 잘못되었습니다.");
            //throw new ResponseStatusException(HttpStatus.NOT_FOUND, "이메일 혹은 비밀번호가 잘못되었습니다.");
            return ResponseEntity.badRequest().body(errorDto);
        }
    }

    @RequestMapping(value = "/login/auth", method = RequestMethod.POST)
    public ResponseEntity<?> tokenVerify(String idToken){
        System.out.println("RequestBody value : " + idToken);
        UserDto user =  principalOauth2UserService.tokenVerify(idToken);
        HttpHeaders res = new HttpHeaders();
        UserSecretDto userDto = null;
        if (user.getEmail() != null) {
            principalOauth2UserService.insertUser(user);
            user = userService.userSelectByEmail(user.getEmail());
            userDto = new UserSecretDto(user.getNo(), user.getEmail(),
                    user.getNickname(), user.getBirth(), user.getProfileImg(),
                    user.getTel(), user.getIntro() , user.getPublish(), user.getMood(), user.getFeedCount());

            TokenDto atJWT = jwtService.create(userDto);
            System.out.println("로그인 컨트롤 atJWT");
            System.out.println(atJWT);
            res.add("at-jwt-access-token", atJWT.getAccessJws());
            res.add("at-jwt-refresh-token", atJWT.getRefreshJws());
            user.setRefreshToken(atJWT.getRefreshJws());
            userService.userRefreshToken(user);
        }

        return ResponseEntity.ok().headers(res).body(user);
    }

    
    /////////////////////////카카오

    @GetMapping(value = "/login/getKakaoAuthUrl")
    public ResponseEntity<?> getKakaoAuthUrl(
            HttpServletRequest request) throws Exception {
        String reqUrl =
                "https://kauth.kakao.com/oauth/authorize"
                        + "?client_id=54115c9fc805ecfb96348d18733e6e4a"
                        + "&redirect_uri=http://localhost:8080/login/oauth_kakao"
                        + "&response_type=code";

        return ResponseEntity.ok().body(reqUrl);
    }

    // 카카오 연동정보 조회
    @RequestMapping(value = "/login/oauth_kakao")
    public ResponseEntity<?> oauthKakao(
            @RequestBody String code) throws Exception {

        System.out.println("#########" + code);
        String access_Token = principalOauth2UserService.getAccessToken(code);
        System.out.println("###access_Token#### : " + access_Token);


        HashMap<String, Object> userInfo = principalOauth2UserService.getUserInfo(access_Token);
        System.out.println("###access_Token#### : " + access_Token);
        System.out.println("###userInfo#### : " + userInfo.get("email"));
        System.out.println("###nickname#### : " + userInfo.get("nickname"));

        JSONObject kakaoInfo =  new JSONObject(userInfo);
        UserDto userDto = new UserDto();
        userDto.setEmail((String) userInfo.get("email"));
        userDto.setNickname((String) userInfo.get("nickname"));
        userDto.setProfileImg((String) userInfo.get("profile_image_url"));
        userDto.setPw(bCryptPasswordEncoder.encode("security"));

        principalOauth2UserService.insertUser(userDto);
        UserDto user = userService.userSelectByEmail(userDto.getEmail());
        UserSecretDto userSecretDto = new UserSecretDto();
        userSecretDto = new UserSecretDto(user.getNo(), user.getEmail(),
                user.getNickname(), user.getBirth(), user.getProfileImg(),
                user.getTel(), user.getIntro() , user.getPublish(), user.getMood(), user.getFeedCount());

        HttpHeaders res = new HttpHeaders();
        TokenDto atJWT = jwtService.create(userSecretDto);
        System.out.println("로그인 컨트롤 atJWT");
        System.out.println(atJWT);
        res.add("at-jwt-access-token", atJWT.getAccessJws());
        res.add("at-jwt-refresh-token", atJWT.getRefreshJws());
        user.setRefreshToken(atJWT.getRefreshJws());
        userService.userRefreshToken(user);

        return ResponseEntity.ok().headers(res).body(kakaoInfo);
    }

    @GetMapping(value = "/qss/list")
    public @ResponseBody String tokenVerify(){
        return "intercept";
    }
}
