package com.ssafy.project.EmotionPlanet.Controller;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import com.ssafy.project.EmotionPlanet.Dto.FollowDto;
import com.ssafy.project.EmotionPlanet.Dto.FollowResultDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import com.ssafy.project.EmotionPlanet.Service.FollowService;

@CrossOrigin(origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"}, allowCredentials = "true", allowedHeaders = "*", methods = {
		RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.HEAD,
		RequestMethod.OPTIONS })
@RestController
public class FollowController {
	@Autowired
	FollowService followService; 

	private static final int SUCCESS = 1;

	@PostMapping(value = "/follows")
	public ResponseEntity<Integer> register(@RequestBody FollowDto followDto) { //팔로우 신청
		if (followService.followRegister(followDto) == SUCCESS) {
			System.out.println("팔로우 성공");
			System.out.println(followDto.getSender()+ "->" +followDto.getReceiver());
			return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
		} else {
			System.out.println("팔로우 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 추가 해주세요.");
		}
	}
	
	@GetMapping(value = {"/follows/{sender}/{receiver}"}) //팔로우 여부 및 정보 체크
	public ResponseEntity<FollowResultDto> select(@PathVariable String sender,@PathVariable String receiver){
		int senderno = Integer.parseInt(sender);
		int receiverno = Integer.parseInt(receiver);
		FollowResultDto dto = followService.select(senderno, receiverno);
		return new ResponseEntity<FollowResultDto>(dto, HttpStatus.OK);
	}
	
	@GetMapping(value = "/follows/{no}")
	public ResponseEntity<List<UserDto>> followselect(@PathVariable String no) { //해당 유저의 팔로우 리스트 출력
		int userNo = Integer.parseInt(no);
		List<UserDto> list = followService.followSelect(userNo);
		if(list.size() != 0) {
			System.out.println("팔로우 유저 있음");
			System.out.println(list.size() +" 명");
			return new ResponseEntity<List<UserDto>>(list, HttpStatus.OK);
		} else {
			System.out.println("팔로우 중인 유저 없음");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "팔로워 중인 사람이 없습니다.");
		}
	}
 
	@GetMapping(value = "/followings/{no}")
	public ResponseEntity<List<UserDto>> followingselect(@PathVariable String no) { //해당 유저의 팔로잉 리스트 출력
		int userNo = Integer.parseInt(no);
		List<UserDto> list = followService.followingSelect(userNo);
		if(list.size() != 0) {
			System.out.println("팔로잉 유저 있음");
			System.out.println(list.size() +" 명");
			return new ResponseEntity<List<UserDto>>(list, HttpStatus.OK);
		} else {
			System.out.println("팔로잉 유저 없음");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "팔로잉 중인 사람이 없습니다.");
		}
	}

	@DeleteMapping(value = "/follows")
	public ResponseEntity<Integer> delete(@RequestBody FollowDto followDto) { //언팔로우
		if(followService.followDelete(followDto) == SUCCESS) {
			System.out.println("언팔로우 성공");
			return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
		} else {
			System.out.println("언팔로우 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 삭제 해주세요.");
		}
	}

	@PutMapping(value = "/follows")
	public ResponseEntity<Integer> update(@RequestBody FollowDto followDto) { //팔로우 수락 
		// => 여기 type도 같이 넘길지 아니면 걍 sender, receiver 만 받아서 할지
		// => 두개만 받으면 쿼리문에서 type 하드코딩해서 넘겨줘야함 
		if(followService.followUpdate(followDto) == SUCCESS) {
			System.out.println("팔로우 수락 성공");
			return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
		} else {
			System.out.println("팔로우 수락 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 수락 해주세요.");
		}
	}
}