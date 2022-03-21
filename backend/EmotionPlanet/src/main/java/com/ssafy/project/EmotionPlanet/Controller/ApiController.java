package com.ssafy.project.EmotionPlanet.Controller;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import com.ssafy.project.EmotionPlanet.Dto.ActivityDto;
import com.ssafy.project.EmotionPlanet.Dto.MovieDto;
import com.ssafy.project.EmotionPlanet.Dto.MusicDto;
import com.ssafy.project.EmotionPlanet.Service.ApiServiceImpl;

@CrossOrigin(origins = {"http://localhost:5500", "https://i6e203.p.ssafy.io"}, allowCredentials = "true", allowedHeaders = "*", methods = {
		RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.HEAD,
		RequestMethod.OPTIONS })

@RestController
@RequestMapping("/recommend")
public class ApiController {

	@Autowired
	ApiServiceImpl apiservice;

	private final int SUCESS = 1;

	@GetMapping(value = "/movieup")
	public ResponseEntity<Integer> movieinsert() { // TMDB에서 인기순으로 500개의 영화를 가져와서 디비에 저장
		if (apiservice.MovieInsert() == SUCESS)
			return new ResponseEntity<Integer>(SUCESS, HttpStatus.OK);
		throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 시도해주세요");
	}

	@GetMapping(value = "/movie/{mood}") // 장르 별로 DB에서 데이터 가져오는거
	public ResponseEntity<List<MovieDto>> Movie(@PathVariable String mood) {
		int moodnumber = Integer.parseInt(mood);
		List<MovieDto> list = apiservice.Movie(moodnumber, 1);
		list.addAll(apiservice.Movie(moodnumber, 0));
		if (list.size() != 0) {
			return new ResponseEntity<List<MovieDto>>(list, HttpStatus.OK);
		} else {
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 시도해주세요");
		}
	}

	@GetMapping(value = "/music/{mood}") // 여기에 감정이랑 뭐 해소 or 심화 감정 데이터 같이 넘겨야 할듯? 갯수 제한도?
	public ResponseEntity<List<MusicDto>> Music(@PathVariable String mood) {
		int moodnumber = Integer.parseInt(mood);
		List<MusicDto> list = apiservice.Music(moodnumber, 1);
		list.addAll(apiservice.Music(moodnumber, 0));
		if (list.size() != 0) {
			return new ResponseEntity<List<MusicDto>>(list, HttpStatus.OK);
		} else {
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 시도해주세요");
		}
	}

	@GetMapping(value = "/activity") // 여기에 감정이랑 뭐 해소 or 심화 감정 데이터 같이 넘겨야 할듯? 갯수 제한도?
	public ResponseEntity<List<ActivityDto>> Activity() {
		List<ActivityDto> list = apiservice.ActivitySelect(1);
		if (list != null) {
			list.addAll(apiservice.ActivitySelect(0));
			return new ResponseEntity<List<ActivityDto>>(list, HttpStatus.OK);
		} else {
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, "다시 시도해주세요");
		}
	}
}