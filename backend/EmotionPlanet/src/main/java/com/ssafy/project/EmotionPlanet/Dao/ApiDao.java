package com.ssafy.project.EmotionPlanet.Dao;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import com.ssafy.project.EmotionPlanet.Dto.ActivityDto;
import com.ssafy.project.EmotionPlanet.Dto.MovieDto;

@Mapper
public interface ApiDao {
	public int MovieInsert(List<MovieDto> list);
	public List<MovieDto> MovieSelect(String genre);
	public List<MovieDto> MovieSelectnomal(String genre);
	public List<ActivityDto> ActivitySelect(int type);
}
