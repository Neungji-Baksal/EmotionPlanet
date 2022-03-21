package com.ssafy.project.EmotionPlanet.Controller;

import com.ssafy.project.EmotionPlanet.Dto.TagDto;
import com.ssafy.project.EmotionPlanet.Service.TagService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;

@CrossOrigin(
        origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"},
        allowCredentials = "true",
        allowedHeaders ="*",
        methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                RequestMethod.DELETE, RequestMethod.HEAD, RequestMethod.OPTIONS }
)
@RestController
public class TagController {

    @Autowired
    TagService tagService;

    private static final int SUCCESS = 1;

    @PostMapping(value ="/tags") // 태그 작성
    public ResponseEntity<Integer> write(@RequestBody TagDto tagDto) {
        int result = tagService.create(tagDto);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "양식이 올바르지 않습니다.");
        }
    }

    @GetMapping(value ="/tags/{no}") // 태그 목록
    public ResponseEntity<List<TagDto>> list(@PathVariable String no) {
        int feedNo = Integer.parseInt(no);
        List<TagDto> tags = tagService.list(feedNo);

        return new ResponseEntity<List<TagDto>>(tags, HttpStatus.OK);
    }

    @GetMapping(value ="/tag/{no}") // 태그
    public ResponseEntity<TagDto> select(@PathVariable String no) {
        int tagNo = Integer.parseInt(no);
        TagDto tag = tagService.select(tagNo);

        return new ResponseEntity<TagDto>(tag, HttpStatus.OK);
    }

}
