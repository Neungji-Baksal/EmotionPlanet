package com.ssafy.project.EmotionPlanet.Dao;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import com.ssafy.project.EmotionPlanet.Dto.FollowDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;

@Mapper
public interface FollowDao {
	public int followRegister(FollowDto followDto);
	public List<UserDto> followSelect(int no);
	public List<UserDto> followingSelect(int no);
	public int followDelete(FollowDto followDto);
	public int followUpdate(FollowDto followDto);
	public FollowDto select(@Param("sender") int sender,@Param("receiver") int receiver);
}
