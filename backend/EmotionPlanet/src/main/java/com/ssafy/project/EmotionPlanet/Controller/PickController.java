package com.ssafy.project.EmotionPlanet.Controller;

import com.ssafy.project.EmotionPlanet.Config.JWT.JwtService;
import com.ssafy.project.EmotionPlanet.Dto.FeedDto;
import com.ssafy.project.EmotionPlanet.Dto.ImgDto;
import com.ssafy.project.EmotionPlanet.Dto.LikeDto;
import com.ssafy.project.EmotionPlanet.Dto.PickDto;
import com.ssafy.project.EmotionPlanet.Service.ImgService;
import com.ssafy.project.EmotionPlanet.Service.PickService;
import com.ssafy.project.EmotionPlanet.Service.S3Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
public class PickController {

    @Autowired
    PickService pickService;

    @Autowired
    JwtService jwtService;

    @Autowired
    S3Service s3Service;

    @Autowired
    ImgService imgService;

    private static final int SUCCESS = 1;

    @PostMapping(value ="/picks") // 목록 생성
    public ResponseEntity<Integer> create(
            @RequestPart(value="data") PickDto pickDto) {

//        List<Integer> imgNo = new ArrayList<>();
//        if(multipartFile != null){
//            imgNo = s3Service.uploadFile(multipartFile);
//        }
//
//        List<ImgDto> imgs = new ArrayList<>();
//        for (int no : imgNo) {
//            imgs.add(imgService.select(no));
//        }
//
//        pickDto.setImgLink(imgs.get(0).getImgLink());

        int result = pickService.create(pickDto);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "양식이 올바르지 않습니다.");
        }
    }

    @GetMapping(value ="/pick/{pickNo}") // 해당 목록 가져오기
    public ResponseEntity<PickDto> list(@RequestHeader(value="at-jwt-access-token") String jwt, @PathVariable String pickNo) {
        int pickNos = Integer.parseInt(pickNo);
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

        PickDto pick = pickService.select(pickNos, Integer.parseInt(userNo));
        if(pick != null) {
            return new ResponseEntity<PickDto>(pick, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "해당 목록이 없습니다.");
        }
    }

    @GetMapping(value ="/picks/user/{no}") // 유저가 만든 목록
    public ResponseEntity<List<PickDto>> userList(@PathVariable String no) {
        int userNo = Integer.parseInt(no);
        List<PickDto> picks = pickService.list(userNo);
        if(picks != null) {
            return new ResponseEntity<List<PickDto>>(picks, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "작성된 목록이 없습니다.");
        }
    }

    @GetMapping(value ="/picks/user/returnNo/{no}") // 유저가 만든 목록 번호
    public ResponseEntity<?> listOnNo(@PathVariable String no) {
        int userNo = Integer.parseInt(no);
        List<Integer> picks = pickService.listOnNo(userNo);
        if(picks != null) {
            return new ResponseEntity<List<Integer>>(picks, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "작성된 목록이 없습니다.");
        }
    }

    @GetMapping(value ="/picks/type/returnNo/{no}/{ty}") // 유저가 만든 목록 번호 by type
    public ResponseEntity<?> listOnNo(@PathVariable String no, @PathVariable String ty) {
        System.out.println("유저가 만든 목록 번호 " + no);
        int userNo = Integer.parseInt(no);
        int type = Integer.parseInt(ty);

        List<Integer> picks = pickService.listByType(userNo, type);
        if(picks != null) {
            return new ResponseEntity<List<Integer>>(picks, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "작성된 목록이 없습니다.");
        }
    }

    @PutMapping(value ="/picks") // 목록 수정
    public ResponseEntity<Integer> update(
            @RequestPart(value="data") PickDto pickDto) {

//        List<Integer> imgNo = new ArrayList<>();
//        if(multipartFile != null){
//            imgNo = s3Service.uploadFile(multipartFile);
//        }
//
//        List<ImgDto> imgs = new ArrayList<>();
//        for (int no : imgNo) {
//            imgs.add(imgService.select(no));
//        }
//
//        pickDto.setImgLink(imgs.get(0).getImgLink());

        int result = pickService.update(pickDto);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "수정에 실패 했습니다.");
        }
    }

    @DeleteMapping(value ="/picks/{no}") // 목록 삭제
    public ResponseEntity<Integer> delete(@PathVariable String no) {
        int pickNo = Integer.parseInt(no);
        int result = pickService.delete(pickNo);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "목록을 찾을 수 없습니다.");
        }
    }

    @PostMapping(value ="/picks/like") // 좋아요
    public ResponseEntity<Integer> like(@RequestBody LikeDto likeDto) {
        int pickNo = likeDto.getTargetNo();
        int userNo = likeDto.getUserNo();

        int result = pickService.like(userNo, pickNo);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "오류 발생.");
        }
    }

    @DeleteMapping(value ="/picks/like") // 좋아요 취소
    public ResponseEntity<Integer> unlike(@RequestBody LikeDto likeDto) {
        int pickNo = likeDto.getTargetNo();
        int userNo = likeDto.getUserNo();

        int result = pickService.unlike(userNo, pickNo);
        if(result == SUCCESS) {
            return new ResponseEntity<Integer>(result, HttpStatus.OK);
        }else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "오류 발생.");
        }
    }
}
