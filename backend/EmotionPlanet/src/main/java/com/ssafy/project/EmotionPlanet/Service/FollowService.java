package com.ssafy.project.EmotionPlanet.Service;

import java.util.List;

import com.ssafy.project.EmotionPlanet.Dto.FollowDto;
import com.ssafy.project.EmotionPlanet.Dto.FollowResultDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;

public interface FollowService {
	public int followRegister(FollowDto followDto);
	public List<UserDto> followSelect(int no);
	public List<UserDto> followingSelect(int no);
	public int followDelete(FollowDto followDto);
	public int followUpdate(FollowDto followDto);
	public FollowResultDto select(int sender, int receiver);
}
