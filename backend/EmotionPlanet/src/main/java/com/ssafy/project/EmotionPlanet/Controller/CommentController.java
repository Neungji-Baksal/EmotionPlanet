package com.ssafy.project.EmotionPlanet.Controller;

import com.ssafy.project.EmotionPlanet.Config.JWT.JwtService;
import com.ssafy.project.EmotionPlanet.Dto.CommentDto;
import com.ssafy.project.EmotionPlanet.Service.CommentServiceImpl;
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
public class CommentController {

    @Autowired
    CommentServiceImpl commentService;

    @Autowired
    JwtService jwtService;

    private static final int SUCCESS = 1;

    @PostMapping(value ="/comments") // 댓글 작성
    public ResponseEntity<Integer> write(@RequestBody CommentDto commentDto) {
        int result = commentService.write(commentDto);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(commentDto.getNo(), HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "글 양식이 올바르지 않습니다.");
        }
    }

    @GetMapping(value ="/comments/{no}") // 댓글 목록
    public ResponseEntity<List<CommentDto>> list(@PathVariable String no) {
        int feedNo = Integer.parseInt(no);
        List<CommentDto> comments = commentService.list(feedNo);

        return new ResponseEntity<List<CommentDto>>(comments, HttpStatus.OK);

//        if(comments != null) {
//            return new ResponseEntity<List<CommentDto>>(comments, HttpStatus.OK);
//        } else {
//            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "댓글이 없습니다.");
//        }
    }

    @GetMapping(value ="/comments/returnNo/{no}") // 댓글 목록
    public ResponseEntity<?> myListReturnNo(@PathVariable String no) {
        int userNo = Integer.parseInt(no);
        List<Integer> comments = commentService.listOnNo(userNo);
        if(comments != null) {
            return new ResponseEntity<List<Integer>>(comments, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "내가 작성한 피드가 없습니다.");
        }
    }

    @GetMapping(value = "/comment/{no}")
    public ResponseEntity<CommentDto> read(@RequestHeader(value="at-jwt-access-token") String jwt, @PathVariable String no) {
        int commentNo = Integer.parseInt(no);

        String decode = jwtService.decode(jwt);
        System.out.println("디코딩 내용 : " + decode);
        String[] arr = decode.split("\\{|\\}| |,|\"|:");
        String userNo = "";
        for(int i = 0; i < arr.length; i++){
            if (arr[i].equals("no")) {
                userNo = arr[i + 2];
                break;
            }
        }

        CommentDto comment = commentService.read(commentNo, Integer.parseInt(userNo));

        return new ResponseEntity<CommentDto>(comment, HttpStatus.OK);
    }

    @PutMapping(value ="/comments") // 댓글 수정
    public ResponseEntity<Integer> update(@RequestBody CommentDto commentDto) {
        int result = commentService.update(commentDto);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "수정에 실패 했습니다.");
        }
    }

    @DeleteMapping(value ="/comments/{no}") // 댓글 삭제
    public ResponseEntity<Integer> delete(@PathVariable String no) {
        int commentNo = Integer.parseInt(no);
        int result = commentService.delete(commentNo);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "피드를 찾을 수 없습니다.");
        }
    }
}
