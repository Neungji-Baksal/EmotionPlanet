package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dao.FeedDao;
import com.ssafy.project.EmotionPlanet.Dao.PickDao;
import com.ssafy.project.EmotionPlanet.Dao.UserDao;
import com.ssafy.project.EmotionPlanet.Dto.FeedDto;
import com.ssafy.project.EmotionPlanet.Dto.FindEmailDto;
import com.ssafy.project.EmotionPlanet.Dto.PickDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {
	
	@Autowired
	UserDao userDao;

	@Autowired
	FeedDao feedDao;

	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	UserServiceImpl(@Lazy BCryptPasswordEncoder bCryptPasswordEncoder){
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }
	
	private static final int SUCCESS = 1;
	private static final int FAIL = -1;

	@Override
	public int userRegister(UserDto userDto) { // 회원 가입
		if (userDao.userRegister(userDto) == SUCCESS) // 성공
			return SUCCESS;
		else // 실패
			return FAIL;
	}

	@Override
	public UserDto userSelect(int no) { // 회원 검색

		UserDto userDto = userDao.userSelect(no);
		List<FeedDto> feedDtos = feedDao.myList(no);
		if(feedDtos == null) userDto.setFeedCount(0);
		else userDto.setFeedCount(feedDtos.size());
		return userDto;
	}

	@Override
	public UserDto userSelectByEmail(String email) {
		UserDto userDto = userDao.userSelectByEmail(email);
		List<FeedDto> feedDtos = feedDao.myList(userDto.getNo());
		if(feedDtos == null) userDto.setFeedCount(0);
		else userDto.setFeedCount(feedDtos.size());

		return userDto;
	}

	@Override
	public int duplicateEmail(String email) { // 이메일 중복 체크
		if (userDao.duplicateEmail(email) == 0) // 사용가능
			return SUCCESS;
		else // 중복
			return FAIL;
	}

	@Override
	public int duplicateNickname(String nickname) { // 닉네임 중복 체크
		if (userDao.duplicateNickname(nickname) == 0) // 사용가능
			return SUCCESS;
		else // 중복
			return FAIL;
	}

	@Override
	public int userDelete(int no) { // 회원 삭제
		if (userDao.userDelete(no) == SUCCESS) 
			return SUCCESS;
		else // 실패
			return FAIL;
	}

	public int userUpdate(UserDto userDto, UserDto changeuserDto) { // 회원 수정
		//변경되는 유정 정보가 넘어왔을때 null또는 0값이 아닌 값 즉 변경되는 값을 찾아 기존 유저정보를 변경함
		if (changeuserDto.getMood() != 0) { // 감정 정보 변경
			System.out.println("===================1번====================== " + changeuserDto.getNo());
			userDto.setMood(changeuserDto.getMood());
		} 
//		else if(changeuserDto.getMood() == 0){
//			System.out.println("===================1.5번====================== " + changeuserDto.getNo());
//			userDto.setMood(changeuserDto.getMood());
//		} 
		else if (changeuserDto.getTel() != null) {  // 구글 로그인 회원 기본 정보 갱신
			System.out.println("===================2번======================");
			userDto.setNickname(changeuserDto.getNickname());
			userDto.setTel(changeuserDto.getTel());
			userDto.setBirth(changeuserDto.getBirth());
		} else if (changeuserDto.getPw() != null && !changeuserDto.getPw().equals("")) { // 비밀번호, 소개글, 공개 여부 변경
			System.out.println("===================3번======================");
			userDto.setNickname(changeuserDto.getNickname());
			userDto.setPw(changeuserDto.getPw());
			userDto.setIntro(changeuserDto.getIntro());
			userDto.setPublish(changeuserDto.getPublish());
		} else if( changeuserDto.getPw() == null) { // 닉네임, 소개글, 공개여부 변경
			System.out.println("===================4번======================");
			userDto.setNickname(changeuserDto.getNickname());
			userDto.setIntro(changeuserDto.getIntro());
			userDto.setPublish(changeuserDto.getPublish());
		}
		if (userDao.userUpdate(userDto) == SUCCESS) // 변경된 기존 유저정보를 가지고 db내용을 변경함
			return SUCCESS;
		else // 실패
			return FAIL;
	}

	@Override
	public int duplicateTel(String tel) { // 전화번호 중복검사
		if (userDao.duplicateTel(tel) == 0) // 사용가능
			return SUCCESS;
		else // 중복
			return FAIL;
	}

	@Override
	public String findEamil(String tel) { // 이메일 찾기
		String email = userDao.findEamil(tel);
		if(email!= null) {
			String[] splitall = email.split("@");
			String[] splitemail = splitall[0].split("");
			String str = "";
			int half = splitemail.length / 2;
			for (int i = 0; i < splitemail.length ; i++) {
				if(i == half-1 || i == half)
					str += "_";
				else
					str += splitemail[i];
			}
			return str+"@"+splitall[1];
		}else
			return null;
	}

	@Override
	public String findPw(FindEmailDto findEmailDto) { // 비밀번호 찾기
		UserDto userDto = userDao.findPw(findEmailDto);
		if(userDto != null) {
			String Pw = randomPassword(); //랜덤 비밀번호 생성
			String encodimgPW = bCryptPasswordEncoder.encode(Pw);
			userDto.setPw(encodimgPW); // dto에 생성된 비밀번호 저장
			System.out.println("여기는 유저 정보"+userDto);
			if(userDao.userUpdate(userDto) == SUCCESS) { // 변경된 비밀번호로 회원 정보 갱신
				return Pw; // 생성된 비밀번호 리턴
			}else {
				return null;
			}   
		}else {
			return null;
		}
	}

	@Override
	public int userRefreshToken(UserDto userDto) {
		return userDao.userRefreshToken(userDto);
	}

	@Override
	public String selectRefreshToken(String email) {
		return userDao.selectRefreshToken(email);
	}

	public String randomPassword(){ //랜덤 비밀번호 생성 메서드
	        char[] charSet = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
	                'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	        String str = "";
	        int idx = 0;
	        for (int i = 0; i < 10; i++) {
	            idx = (int) (charSet.length * Math.random());
	            str += charSet[idx];
	        }
	        return str;
	    }
}


//	@Override
//	public int userUpdate(UserDto userDto, UserDto changeuserDto) { // 회원 수정
//		//변경되는 유정 정보가 넘어왔을때 null또는 0값이 아닌 값 즉 변경되는 값을 찾아 기존 유저정보를 변경함
//		if (changeuserDto.getMood() != 0) { // 감정 정보 변경
//			userDto.setMood(changeuserDto.getMood());
//		} else if (changeuserDto.getTel() != null) {  // 구글 로그인 회원 기본 정보 갱신
//			userDto.setNickname(changeuserDto.getNickname());
//			userDto.setTel(changeuserDto.getTel());
//			userDto.setBirth(changeuserDto.getBirth());
//		} else if (changeuserDto.getPw() != null) { // 비밀번호, 소개글, 공개 여부 변경
//			userDto.setNickname(changeuserDto.getNickname());
//			userDto.setPw(changeuserDto.getPw());
//			userDto.setIntro(changeuserDto.getIntro());
//			userDto.setPublish(changeuserDto.getPublish());
//		} else { // 닉네임, 소개글, 공개여부 변경
//			userDto.setNickname(changeuserDto.getNickname());
//			userDto.setIntro(changeuserDto.getIntro());
//			userDto.setPublish(changeuserDto.getPublish());
//		}
//		if (userDao.userUpdate(userDto) == SUCCESS) // 변경된 기존 유저정보를 가지고 db내용을 변경함
//			return SUCCESS;
//		else // 실패
//			return FAIL;
//	}