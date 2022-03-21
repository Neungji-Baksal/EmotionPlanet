package com.ssafy.project.EmotionPlanet.Controller;

import com.ssafy.project.EmotionPlanet.Config.JWT.JwtService;
import com.ssafy.project.EmotionPlanet.Dto.FindEmailDto;
import com.ssafy.project.EmotionPlanet.Dto.TokenDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import com.ssafy.project.EmotionPlanet.Dto.UserSecretDto;
import com.ssafy.project.EmotionPlanet.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@CrossOrigin(origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"}, allowCredentials = "true", allowedHeaders = "*", methods = {
		RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.HEAD,
		RequestMethod.OPTIONS })
@RestController
public class UserController {
	@Autowired
	UserService userService;

	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder;

	@Autowired
	private JavaMailSender javaMailSender;

	@Autowired
	JwtService jwtService;
	
	private static final int SUCCESS = 1;

	@PostMapping(value = "/register") // 회원가입
	public ResponseEntity<Integer> register(@RequestBody UserDto userDto) {
		String rawPassword = userDto.getPw();
		String enPassword = bCryptPasswordEncoder.encode(rawPassword);
		userDto.setPw(enPassword);

		if (userService.userRegister(userDto) == SUCCESS) {
			System.out.println("회원 가입 성공");
			System.out.println(userDto); 
			return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
		} else {
			System.out.println("회원 가입 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "가입 양식이 올바르지 않습니다.");
		}
	}

	@GetMapping(value = "/users/{no}") // 회원번호로 회원 정보 반환
	public ResponseEntity<UserSecretDto> select(@PathVariable String no) {
		int userNo = Integer.parseInt(no);
		UserDto userDto = userService.userSelect(userNo);
		UserSecretDto userSecretDto = new UserSecretDto(userDto.getNo(), userDto.getEmail(), userDto.getNickname(),
				userDto.getBirth(), userDto.getProfileImg(), userDto.getTel(), userDto.getIntro()
				, userDto.getPublish(), userDto.getMood(), userDto.getFeedCount());
		if (userSecretDto.getEmail() != null) {
			System.out.println("회원 번호 검색 성공");
			System.out.println(userSecretDto);
			return new ResponseEntity<UserSecretDto>(userSecretDto, HttpStatus.OK);
		} else {
			System.out.println("회원 번호 검색 실패");
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 유저가 없습니다.");
		}
	}
	
	@GetMapping(value = "/register/checkByEmail/{email}") // 이메일 중복검사
	public ResponseEntity<Integer> duplicateEmail(@PathVariable String email) {
		if (userService.duplicateEmail(email) == SUCCESS) {
			System.out.println("이메일 중복 검사 미사용 " + email);
			return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
		} else {
			System.out.println("이메일 중복 검사 사용중 " + email);
			throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 사용중인 이메일 입니다.");
		}
	} 

	@GetMapping(value = "/register/checkByNickname/{nickname}") // 닉네임 중복검사
	public ResponseEntity<Integer> duplicateNickname(@PathVariable String nickname) {
		if (userService.duplicateNickname(nickname) == SUCCESS) {
			System.out.println("닉네임 중복 검사 미사용 " + nickname);
			return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
		} else {
			System.out.println("닉네임 중복 검사 사용중 " + nickname);
			throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 사용중인 닉네임 입니다.");
		}
	}
	
	@GetMapping(value = "/register/checkByTel/{tel}") // 전화번호 중복검사
	public ResponseEntity<Integer> duplicateTel(@PathVariable String tel) {
		if (userService.duplicateTel(tel) == SUCCESS) {
			System.out.println("전화번호 중복 검사 미사용 " + tel);
			return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
		} else {
			System.out.println("전화번호 중복 검사 사용중 " + tel);
			throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 사용중인 전화번호 입니다.");
		}
	}
	
	@PutMapping(value ="/users/update") //회원 수정
	public ResponseEntity<?> update(@RequestBody UserDto changeuserDto) {
		System.out.println("여기를 못오나?");
		System.out.println(changeuserDto.getNo());
		System.out.println(changeuserDto.getMood());
		HttpHeaders res = new HttpHeaders();

		if(changeuserDto.getPw() != null) {
			String rawPassword = changeuserDto.getPw();
			String enPassword = bCryptPasswordEncoder.encode(rawPassword);
			changeuserDto.setPw(enPassword);
		} 
		UserDto userDto = userService.userSelect(changeuserDto.getNo()); //입력받은 유저 번호로 기존 유저 정보 가져옴
		System.out.println(userDto);
		if(userService.userUpdate(userDto, changeuserDto) == SUCCESS) { // 기존정보와 입력받은 정보를 비교해서 새로 갱신
			String accessToken = jwtService.createAccess(userDto.getEmail());
			System.out.println("==============업데이트 엑세스 토큰 ==========" + "\n" + accessToken);
			res.add("at-jwt-access-token", accessToken);
			userDto.setPw(null);
			return ResponseEntity.ok().headers(res).body(userDto);
		}else {
			System.out.println("회원 수정 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "수정할 내용을 확인해 주세요.");
		}
	}
	
	@DeleteMapping(value = "/users/{no}") //회원 탈퇴 회원 번호로 회원 정보 삭제
	public ResponseEntity<Integer> delete(@PathVariable String no) { 
		int userNo = Integer.parseInt(no);
		if (userService.userDelete(userNo) == SUCCESS) {
			System.out.println("회원 탈퇴 성공");
			System.out.println("회원 번호" + no);
			return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
		} else {
			System.out.println("회원 탈퇴 실패");
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 유저가 없습니다.");
		}
	}
	
	@GetMapping(value = "/register/findEmail/{tel}") // 이메일 찾기
	public ResponseEntity<String> findemail(@PathVariable String tel) {
		System.out.println(tel);
		String email = userService.findEamil(tel);
		if(email != null) {
			System.out.println("이메일 찾기 성공");
			System.out.println("이메일 : "+ email);
			return new ResponseEntity<String>(email, HttpStatus.OK);
		} else {
			System.out.println("이메일 찾기 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "전화 번호를 확인해 주세요.");
		}
	}
	
	@PostMapping(value = "/register/findPw") // 비밀번호 찾기
	public void sendmail(@RequestBody FindEmailDto findEmailDto) {
		String Pw = userService.findPw(findEmailDto);
		if(Pw != null) {
			System.out.println("비밀번호 찾기 성공");
			SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
			simpleMailMessage.setTo(findEmailDto.getRequestemail());
			simpleMailMessage.setSubject("Emotion Planet 비밀번호 안내 메일입니다.");
			simpleMailMessage.setText("신규 비밀번호 : "+Pw+"\n 로그인 후 비밀번호를 변경해 주세요.");
			javaMailSender.send(simpleMailMessage);
			System.out.println("이메일 전송 완료");
			throw new ResponseStatusException(HttpStatus.OK, "이메일을 확인하세요.");
		}else {
			System.out.println("비밀번호 찾기 실패");
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 유저가 없습니다.");
		}
	}
}