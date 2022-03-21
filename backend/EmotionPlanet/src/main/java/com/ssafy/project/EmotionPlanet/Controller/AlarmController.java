package com.ssafy.project.EmotionPlanet.Controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.ssafy.project.EmotionPlanet.Dto.AlarmDto;
import com.ssafy.project.EmotionPlanet.Service.AlarmService;

@RestController
public class AlarmController {
	
	@Autowired
	AlarmService alarmService;
	
	 private static final int SUCCESS = 1;
	
    @MessageMapping("/alarm/send/{no}") // 메시지 받을 mapping 주소
    @SendTo("/alarm/receive/{no}") // 메시지를 url 로 반환
    // SocketHandler는 1) /receive에서 메시지를 받고, /send로 메시지를 보내줍니다.
    // 정의한 SocketVO를 1) 인자값, 2) 반환값으로 사용합니다.
    public AlarmDto insertAlram(@DestinationVariable int no,@RequestParam AlarmDto alarmDto) { //pathvriable 친구
        System.out.println(alarmDto);
        AlarmDto dto = alarmService.insertAlram(alarmDto);
        System.out.println(dto);
        if(dto != null) {
        	return dto;
        }else {
        	throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 시도해주세요");
        }
    }
     
    @GetMapping(value = "/alarm/{no}")
    public ResponseEntity<List<AlarmDto>> selectAlram(@PathVariable String no) {
        System.out.println("알람 : " + no);
        int userNo = Integer.parseInt(no);
        List<AlarmDto> list = alarmService.selectAlram(userNo);
        if(list != null) {
        	System.out.println("알림 성공");
        	return new ResponseEntity<List<AlarmDto>>(list, HttpStatus.OK);
        }else {
        	System.out.println("알림 실패");
        	throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 시도해주세요");
        }
    }
    
    @GetMapping(value = "/alarm/read/{receiver}")
    public ResponseEntity<Integer> readAlram(@PathVariable String receiver) { 
        int Receiver = Integer.parseInt(receiver);
        int result = alarmService.readanddeleteAlram(Receiver);
        if(result == SUCCESS) {
        	System.out.println("알림 읽기 성공");
        	return new ResponseEntity<Integer>(SUCCESS, HttpStatus.OK);
        }else {
        	System.out.println("알림 읽기 실패");
        	throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 시도해주세요");
        }
    }
    
    @DeleteMapping(value = "/alarm/{no}")
    public ResponseEntity<Integer> deleteAlram(@PathVariable String no) { 
    	System.out.println("gdg");
        int userNo = Integer.parseInt(no);
        int result = alarmService.deleteAlram(userNo);
        if(result == SUCCESS) {
        	System.out.println("알림 삭제 성공");
        	return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
        	System.out.println("알림 삭제 실패");
        	throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 시도해주세요");
        }
    }

}