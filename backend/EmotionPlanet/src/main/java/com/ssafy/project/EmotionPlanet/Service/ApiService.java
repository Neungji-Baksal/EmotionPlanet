package com.ssafy.project.EmotionPlanet.Service;

import java.util.List;
import com.ssafy.project.EmotionPlanet.Dto.ActivityDto;
import com.ssafy.project.EmotionPlanet.Dto.MovieDto;
import com.ssafy.project.EmotionPlanet.Dto.MusicDto;

public interface ApiService {
	public List<MusicDto> Music(int mood, int type);
	public List<MovieDto> Movie(int mood, int type);
	public List<ActivityDto> ActivitySelect(int type);
	public int MovieInsert();
}