package com.ssafy.project.EmotionPlanet.Controller;

import java.util.List;
import com.ssafy.project.EmotionPlanet.Dto.TestDto;
import com.ssafy.project.EmotionPlanet.Service.TestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@CrossOrigin(
        origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"},
        allowCredentials = "true",
        allowedHeaders = "*",
        methods = { RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                RequestMethod.DELETE, RequestMethod.HEAD, RequestMethod.OPTIONS })

@RestController 
public class TestController {

    @Autowired
    TestService testService;

    @GetMapping(value = "/test")
    public ResponseEntity<List<TestDto>> step1() {
    	List<TestDto> list = testService.step1();
    	if (list.size() != 0) {
			System.out.println("첫 번째 테스트 가져오기 성공");
			System.out.println(list.size());
			System.out.println(list);
			return new ResponseEntity<List<TestDto>>(list, HttpStatus.OK);
		}else {
			System.out.println("첫 번째 테스트 가져오기 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "잘못된 접근입니다.");
		}
    }
    
    @PostMapping(value = "/detailtest")
    public ResponseEntity<List<TestDto>> step2(@RequestBody  List<TestDto> testDto){
    	List<TestDto> list = testService.step2(testDto);
    	if (list.size() != 0) {
			System.out.println("두 번째 테스트 가져오기 성공");
			System.out.println(list.size());
			System.out.println(list);
			return new ResponseEntity<List<TestDto>>(list, HttpStatus.OK);
		}else {
			System.out.println("두 번째 테스트 가져오기 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "잘못된 접근입니다.");
		}
    }
    
    @PostMapping(value = "/resulttest")
    public ResponseEntity<TestDto> step3(@RequestBody  List<TestDto> testDto){
    	
    	TestDto dto = testService.step3(testDto);
    	if (dto != null) {
			System.out.println("마지막 테스트 가져오기 성공");
			System.out.println(dto);
			return new ResponseEntity<TestDto>(dto, HttpStatus.OK);
		}else {
			System.out.println("마지막 테스트 가져오기 실패");
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "잘못된 접근입니다.");
		}
    }
}
