package com.ssafy.project.EmotionPlanet.Service;

import java.util.List;
import java.util.Map;

import com.ssafy.project.EmotionPlanet.Dto.FeedDto;
import com.ssafy.project.EmotionPlanet.Dto.TagDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;

public interface SearchService {
	public List<TagDto> tagSelect(String name);
	public List<FeedDto> tagfeedSelect(String name, int userNo);
	public List<UserDto> userSelect(String name);
	public List<TagDto> picktagSelect();
	public List<Map<String, Object>> pickSelect(String name);
//	public List<PickDto> recommendSelect(String name);
}