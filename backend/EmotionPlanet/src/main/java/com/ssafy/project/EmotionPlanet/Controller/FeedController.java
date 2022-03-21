package com.ssafy.project.EmotionPlanet.Controller;

import com.ssafy.project.EmotionPlanet.Config.JWT.JwtService;
import com.ssafy.project.EmotionPlanet.Dto.*;
import com.ssafy.project.EmotionPlanet.Service.FeedService;
import com.ssafy.project.EmotionPlanet.Service.ImgService;
import com.ssafy.project.EmotionPlanet.Service.S3Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;

@CrossOrigin(
        origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"},
        allowCredentials = "true",
        allowedHeaders ="*",
        methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                RequestMethod.DELETE, RequestMethod.HEAD, RequestMethod.OPTIONS }
)
@RestController
public class FeedController {
    @Autowired
    FeedService feedService;

    @Autowired
    S3Service s3Service;

    @Autowired
    ImgService imgService;

    @Autowired
    JwtService jwtService;

    private static final int SUCCESS = 1;

    @PostMapping(value ="/feeds") // 글 작성
    public ResponseEntity<Integer> write(@RequestBody FeedDto feedDto) {

        System.out.println("===========피드 작성====================");
        System.out.println(feedDto.toString());
        int result = feedService.write(feedDto);
        if(result != 0) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "글 양식이 올바르지 않습니다.");
        }
    }
    
    

    @GetMapping(value ="/feeds/{no}") // 최신 피드 목록
    public ResponseEntity<List<FeedDto>> list(@PathVariable String no) {
        int userNo = Integer.parseInt(no);
        List<FeedDto> feeds = feedService.list(userNo);
        if(feeds != null) {
            return new ResponseEntity<List<FeedDto>>(feeds, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "최신피드가 없습니다.");
        }
    }

    @GetMapping(value ="/feeds/returnNo/{no}") // 최신 피드 목록
    public ResponseEntity<List<Integer>> listReturnNo(@PathVariable String no) {
        int userNo = Integer.parseInt(no);
        List<Integer> feeds = feedService.listReturnNo(userNo);
        if(feeds != null) {
            return new ResponseEntity<List<Integer>>(feeds, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "최신피드가 없습니다.");
        }
    }

    @GetMapping(value ="/feeds/my/returnNo/{no}") // 내가 작성한 피드 목록
    public ResponseEntity<List<Integer>> myListReturnNo(@PathVariable String no) {
        int userNo = Integer.parseInt(no);
        List<Integer> feeds = feedService.myListReturnNo(userNo);
        if(feeds != null) {
            return new ResponseEntity<List<Integer>>(feeds, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "내가 작성한 피드가 없습니다.");
        }
    }

    @GetMapping(value ="/feeds/my/{no}") // 내가 작성한 피드 목록
    public ResponseEntity<List<FeedDto>> myList(@RequestHeader(value="at-jwt-access-token") String jwt,@PathVariable String no) {
        int userNo = Integer.parseInt(no);

        String decode = jwtService.decode(jwt);
        System.out.println("디코딩 내용 : " + decode);
        String[] arr = decode.split("\\{|\\}| |,|\"|:");
        String myNo = "";
        for(int i = 0; i < arr.length; i++){
            if (arr[i].equals("no")) {
                myNo = arr[i + 2];
                break;
            }
        }

        List<FeedDto> feeds = feedService.myList(userNo, Integer.parseInt(myNo));
        if(feeds != null) {
            return new ResponseEntity<List<FeedDto>>(feeds, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "내가 작성한 피드가 없습니다.");
        }
    }


    @GetMapping(value ="/feed/{no}") // 피드 정보
    public ResponseEntity<FeedDto> read(@RequestHeader(value="at-jwt-access-token") String jwt, @PathVariable String no) {

        int feedNo = Integer.parseInt(no);
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

        FeedDto feed = feedService.read(feedNo, Integer.parseInt(userNo));
        List<UserRequestDto> likeList = feedService.likeList(feedNo);
        feed.setLikes(likeList);
        if(feed != null) {
            return new ResponseEntity<FeedDto>(feed, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "피드가 없습니다.");
        }
    }

    @GetMapping(value = "/feeds/like/{no}")
    public ResponseEntity<List<UserRequestDto>> likeList(@PathVariable String no) {
        int feedNo = Integer.parseInt(no);
        List<UserRequestDto> users = feedService.likeList(feedNo);

        return new ResponseEntity<List<UserRequestDto>>(users, HttpStatus.OK);

//        if(users != null) {
//            return new ResponseEntity<List<UserDto>>(users, HttpStatus.OK);
//        } else {
//            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "좋아요 목록이 없습니다.");
//        }
    }

    @PutMapping(value ="/feeds") // 글 수정
    public ResponseEntity<Integer> update(
            @RequestPart(value="userInfo") FeedDto feedDto,
            @RequestPart(value="multipartFile", required = false) List<MultipartFile> multipartFile) {

        List<Integer> imgNo = new ArrayList<>();
        if(multipartFile != null){
            imgNo = s3Service.uploadFile(multipartFile);
        }

        List<ImgDto> imgs = new ArrayList<>();
        for (int no : imgNo) {
            imgs.add(imgService.select(no));
        }


        int result = 0;
        if(imgs.size() != 0) {
            feedDto.setImgs(imgs);
            result = feedService.update(feedDto, 0);
        }
        else {
            FeedDto now = feedService.read(feedDto.getNo(), feedDto.getAuthor());
            feedDto.setImgs(now.getImgs());
            result = feedService.update(feedDto, 1);
        }


        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "수정에 실패 했습니다.");
        }
    }

    @DeleteMapping(value ="/feeds/{no}") // 피드 삭제
    public ResponseEntity<Integer> delete(@PathVariable String no) {
        int feedNo = Integer.parseInt(no);
        int result = feedService.delete(feedNo);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "피드를 찾을 수 없습니다.");
        }
    }

    @PostMapping(value ="/feeds/like") // 좋아요
    public ResponseEntity<Integer> like(@RequestBody LikeDto likeDto) {
        int feedNo = likeDto.getTargetNo();
        int userNo = likeDto.getUserNo();

        int result = feedService.like(userNo, feedNo);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "오류 발생.");
        }
    }

    @DeleteMapping(value ="/feeds/like") // 좋아요 취소
    public ResponseEntity<Integer> unlike(@RequestBody LikeDto likeDto) {
        int feedNo = likeDto.getTargetNo();
        int userNo = likeDto.getUserNo();

        int result = feedService.unlike(userNo, feedNo);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "오류 발생.");
        }
    }

}
