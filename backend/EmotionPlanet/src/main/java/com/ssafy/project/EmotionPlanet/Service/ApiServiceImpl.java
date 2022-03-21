package com.ssafy.project.EmotionPlanet.Service;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import com.ssafy.project.EmotionPlanet.Dao.ApiDao;
import com.ssafy.project.EmotionPlanet.Dto.ActivityDto;
import com.ssafy.project.EmotionPlanet.Dto.MovieDto;
import com.ssafy.project.EmotionPlanet.Dto.MusicDto;
import com.ssafy.project.EmotionPlanet.Util.createAccesstoken;

@Service
public class ApiServiceImpl implements ApiService {

	@Autowired
	ApiDao apiDao;

	private final RestTemplate restTemplate = new RestTemplate();

	private String[][] musicemotion = new String[][] {
			{ "happy", "sad" }, // 행복 너무행복해서 슬프려한다?
			{ "sad", "happy" }, // 우울
			{ "k-pop", "k-pop" }, // 중립
			{ "goth", "acoustic" }, // 공포
			{ "edm", "classical" }, // 깜짝
			{ "rock-n-roll", "funk" }, // 분노
			{ "k-pop", "k-pop" } // 우주선
	};
	// https://api.themoviedb.org/3/genre/movie/list?api_key=a571ca19d9fd38ff2298025d4a8475f5
	private String[][] movieemotion = new String[][] {
			{ "35", "18" }, // 행복 Comedy Drama
			{ "18", "35" }, // 우울 Drama Comedy
			{ "", "" }, // 중립은 그냥 둘다 추천? => 최신 개봉한거 위주
			{ "27", "10751" }, // 공포 Horror, Family
			{ "9648", "10402" }, // 깜짝 Mystery, Music
			{ "10752", "16" }, // 분노 War Animation
			{ "", "" }, // 우주선
	};

	@Override
	public List<MusicDto> Music(int mood, int type) {
		String URL = "https://api.spotify.com/v1/recommendations/?seed_genres=" + musicemotion[mood-1][type]
				+ "&limit=10&market=KR";
		createAccesstoken create = new createAccesstoken();
		final HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", "Bearer " + create.accesstoken());
		final HttpEntity<String> entity = new HttpEntity<String>(headers);
		String str = restTemplate.exchange(URL, HttpMethod.GET, entity, String.class).getBody();
		List<MusicDto> list = new ArrayList<>();
		try {
			JSONParser jsonParser = new JSONParser();
			JSONObject jsonObject = (JSONObject) jsonParser.parse(str); // API를 통해 넘어온 JSON을 파싱
			JSONArray track = (JSONArray) jsonObject.get("tracks"); // JSON 파싱 데이터에서 tracks부분을 배열로 가져옴
			for (int i = 0; i < track.size(); i++) {
				JSONObject trackbody = (JSONObject) track.get(i); // 가져온 배열에서 첫번째 부분만 가져옴
				JSONObject albumbody = (JSONObject) trackbody.get("album"); // 위에서 가져온 데이터에서 앨범 부분만 가져와서 저장 여기에 앨범제목
																			// 출시일은 그냥 있고 이미지 아티스트는 배열형태
				JSONArray image = (JSONArray) albumbody.get("images"); // 이미지 부분을 배열로 가져옴
				JSONObject imagebody = (JSONObject) image.get(0);
				JSONArray artist = (JSONArray) albumbody.get("artists"); // 아티스트 부분을 배열로 가져옴
				JSONObject artistbody = (JSONObject) artist.get(0);
				MusicDto dto = new MusicDto();
				dto.setArtist(artistbody.get("name").toString());
				dto.setTitle(trackbody.get("name").toString());
				dto.setYear(albumbody.get("release_date").toString());
				dto.setImgLink(imagebody.get("url").toString());
				list.add(dto);
			}
			JSONArray seed = (JSONArray) jsonObject.get("seeds");
			JSONObject seedbody = (JSONObject) seed.get(0);
			System.out.println(seedbody.get("id"));
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return list;
	}

	@Override
	public List<MovieDto> Movie(int mood, int type) {
		List<MovieDto> list = null;
		if(mood == 3) {
			list = apiDao.MovieSelectnomal(movieemotion[mood-1][type]); // 여기가 중립
 		}else {
			list = apiDao.MovieSelect(movieemotion[mood-1][type]);
		}
		if (list.size() != 0)
			return list;
		return null;
	}

	@Override
	public int MovieInsert() { // 그 공백 데이터 지우고 19세 adult 이부분 체크하기
		String key = "a571ca19d9fd38ff2298025d4a8475f5";
		LocalDate now = LocalDate.now();
		List<MovieDto> list = new ArrayList<MovieDto>();
		for (int page = 1; page <= 25; page++) {
			String apiURL = "https://api.themoviedb.org/3/movie/popular?api_key=" + key + "&language=ko-KR&page="
					+ page;
			final HttpHeaders headers = new HttpHeaders();
			final HttpEntity<String> entity = new HttpEntity<String>(headers);
			String str = restTemplate.exchange(apiURL, HttpMethod.GET, entity, String.class).getBody();
			try {
				JSONParser jsonParser = new JSONParser();
				JSONObject jsonObject = (JSONObject) jsonParser.parse(str); // API를 통해 넘어온 JSON을 파싱
				JSONArray result = (JSONArray) jsonObject.get("results"); // JSON 파싱 데이터에서 tracks부분을 배열로 가져옴
				for (int i = 0; i < result.size(); i++) {
					JSONObject resultbody = (JSONObject) result.get(i);
					if (!resultbody.containsKey("release_date") || !resultbody.containsKey("genre_ids") || resultbody.get("overview").toString().equals("") ||
							resultbody.get("poster_path") == null || resultbody.get("genre_ids").toString().equals("[]"))
						continue;
					LocalDate day = LocalDate.parse(resultbody.get("release_date").toString());
					if(now.isBefore(day))
						continue;
					MovieDto dto = new MovieDto();
					dto.setNo(Integer.parseInt(resultbody.get("id").toString()));
					dto.setTitle(resultbody.get("title").toString());
					dto.setDescr(resultbody.get("overview").toString());
					dto.setImgLink("https://image.tmdb.org/t/p/original" + resultbody.get("poster_path"));
					dto.setYear(resultbody.get("release_date").toString());
					dto.setGenre(resultbody.get("genre_ids").toString());
					list.add(dto);
				}
			} catch (ParseException e) {
				e.printStackTrace();
			}
		}
		System.out.println(list.size());
		int result = apiDao.MovieInsert(list);
		return result;
	}

	@Override
	public List<ActivityDto> ActivitySelect(int type) {
		List<ActivityDto> list = apiDao.ActivitySelect(type);
		if (list.size() != 0)
			return list;
		return null;
	}
}

/*
 * 행복(happy) &max_energy=0.99&min_energy=0.7&max_valence=0.99&min_valence=0.9&
 * max_danceability=0.99&min_danceability=0.7"; 우울(sad)
 * &max_energy=0.2&min_energy=0.0&max_valence=0.15&min_valence=0.0&
 * max_danceability=0.3&min_danceability=0.0";
 * 
 * 공포(goth|acoustic)
 * &max_energy=0.75&min_energy=0.65&max_valence=0.35&min_valence=0.25&
 * max_danceability=0.75&min_danceability=0.65";
 * 
 * 놀람 &max_energy=0.99&min_energy=0.8&max_valence=0.6&min_valence=0.5&
 * max_danceability=0.9&min_danceability=0.8";
 * 
 * 분노 &max_energy=0.6&min_energy=0.5&max_valence=0.25&min_valence=0.15&
 * max_danceability=0.6&min_danceability=0.5";
 * 
 * 중립(인기도) &max_energy=0.55&min_energy=0.45&max_valence=0.55&min_valence=0.45&
 * max_danceability=0.55&min_danceability=0.45";
 */