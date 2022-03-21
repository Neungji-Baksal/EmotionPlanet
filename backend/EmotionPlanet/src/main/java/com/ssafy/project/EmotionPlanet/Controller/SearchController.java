package com.ssafy.project.EmotionPlanet.Controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import com.ssafy.project.EmotionPlanet.Dto.FeedDto;
import com.ssafy.project.EmotionPlanet.Dto.TagDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;
import com.ssafy.project.EmotionPlanet.Service.SearchService;

@CrossOrigin(origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"}, allowCredentials = "true", allowedHeaders = "*", methods = {
		RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.HEAD,
		RequestMethod.OPTIONS })

@RestController
public class SearchController {
	@Autowired
	SearchService searchService;

	@GetMapping(value = "/searchs/byTag/{name}")  //태그 검색 => 해당 태그명이 포함된 태그 리스트 + 태그 사용된 피드 갯수 리턴
	public ResponseEntity<List<TagDto>> tagSelect(@PathVariable String name) {
		List<TagDto> list = searchService.tagSelect(name);
		if (list != null) {
			System.out.println("태그 검색 성공");
			System.out.println(list);
			return new ResponseEntity<List<TagDto>>(list, HttpStatus.OK);
		} else {
			System.out.println("태그 검색 실패");
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 정보가 없습니다.");
		}
	}
	
	@GetMapping(value = "/searchs/byTag/feed/{no}/{name}")  //태그로 피드 정보들 다 가져오기
	public ResponseEntity<List<FeedDto>> tagListSelect(@PathVariable String no,@PathVariable String name) {
		int userNo = Integer.parseInt(no);
		List<FeedDto> list = searchService.tagfeedSelect(name, userNo);
		if (list != null) {
			System.out.println("태그포함 피드 검색 성공");
//			System.out.println(list);
			return new ResponseEntity<List<FeedDto>>(list, HttpStatus.OK);
		} else {
			System.out.println("태그포함 피드 검색 실패");
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 정보가 없습니다.");
		}
	}
	
	@GetMapping(value = "/searchs/byNickName/{name}")  //유저 검색
	public ResponseEntity<List<UserDto>> userSelect(@PathVariable String name) {
		List<UserDto> list = searchService.userSelect(name);
		if (list != null) {
			System.out.println("유저 검색 성공");
			System.out.println(list);
			return new ResponseEntity<List<UserDto>>(list, HttpStatus.OK);
		} else {
			System.out.println("유저 검색 실패");
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 정보가 없습니다.");
		}
	}
	
	@GetMapping(value = "/searchs/byPickTagList")  // 픽 정보 가져오기
	public ResponseEntity<List<TagDto>> picktagListSelect() {
		List<TagDto> list = searchService.picktagSelect();
		if (list != null) {
			System.out.println("찜목록 태그 리스트 검색 성공");
			System.out.println(list);
			return new ResponseEntity<List<TagDto>>(list, HttpStatus.OK);
		} else {
			System.out.println("찜목록 태그 검색 실패");
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 정보가 없습니다.");
		}
	}
	
	@GetMapping(value = "/searchs/byPickTag/{name}")  // 픽 정보 가져오기
	public ResponseEntity<List<Map<String, Object>>> picktagSelect(@PathVariable String name) {
		List<Map<String, Object>> list = searchService.pickSelect(name);
		if (list != null) {
			System.out.println("찜목록 태그 리스트 검색 성공");
			System.out.println(list);
			return new ResponseEntity<List<Map<String, Object>>>(list, HttpStatus.OK);
		} else {
			System.out.println("찜목록 태그 검색 실패");
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 정보가 없습니다.");
		}
	}
	
	
//	@GetMapping(value = "/searchs/byRecommend/{name}")  //찜목록 태그 검색
//	public ResponseEntity<List<PickDto>> recommendSelect(@PathVariable String name) {
//		List<PickDto> list = searchService.recommendSelect(name);
//		if (list != null) {
//			System.out.println("찜목록 검색 성공");
//			System.out.println(list);
//			return new ResponseEntity<List<PickDto>>(list, HttpStatus.OK);
//		} else {
//			System.out.println("찜목록 검색 실패");
//			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하는 정보가 없습니다.");
//		}
//	}
}