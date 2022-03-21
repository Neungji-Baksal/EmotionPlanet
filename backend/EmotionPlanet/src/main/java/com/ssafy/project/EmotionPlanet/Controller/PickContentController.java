package com.ssafy.project.EmotionPlanet.Controller;

import com.ssafy.project.EmotionPlanet.Dto.PickContentDto;
import com.ssafy.project.EmotionPlanet.Service.PickContentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@CrossOrigin(
        origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"},
        allowCredentials = "true",
        allowedHeaders ="*",
        methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                RequestMethod.DELETE, RequestMethod.HEAD, RequestMethod.OPTIONS }
)
@RestController
public class PickContentController {


    @Autowired
    PickContentService pickContentService;

    private static final int SUCCESS = 1;

    @GetMapping(value ="/pickContent/{no}") // 컨텐츠 선택
    public ResponseEntity<PickContentDto> select(@PathVariable String no) {
        int contentNo = Integer.parseInt(no);
        PickContentDto pickContentDto = pickContentService.select(contentNo);
        if(pickContentDto != null) {
            return new ResponseEntity<PickContentDto>(pickContentDto, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "해당 컨텐츠를 찾을 수 없습니다.");
        }
    }

    @PostMapping(value ="/pickContent") // 컨텐츠 추가
    public ResponseEntity<?> create(@RequestBody PickContentDto pickContentDto) {
        String year = pickContentDto.getYear();
        if(year != null)pickContentDto.setYear(year.substring(0, 4));

        System.out.println(pickContentDto.toString());

        int result = pickContentService.create(pickContentDto);
        if(result != 0) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "해당 컨텐츠를 찾을 수 없습니다.");
        }
    }

    @DeleteMapping(value ="/pickContent/{no}") // 컨텐츠 삭제
    public ResponseEntity<Integer> delete(@RequestBody PickContentDto pickContentDto) {
        int result = pickContentService.delete(pickContentDto);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "해당 컨텐츠를 찾을 수 없습니다.");
        }
    }
}
