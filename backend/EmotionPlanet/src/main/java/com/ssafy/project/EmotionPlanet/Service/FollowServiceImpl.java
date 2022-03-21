package com.ssafy.project.EmotionPlanet.Service;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.ssafy.project.EmotionPlanet.Dao.FollowDao;
import com.ssafy.project.EmotionPlanet.Dao.UserDao;
import com.ssafy.project.EmotionPlanet.Dto.FollowDto;
import com.ssafy.project.EmotionPlanet.Dto.FollowResultDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;

@Service
public class FollowServiceImpl implements FollowService {

	@Autowired
	FollowDao followDao;
	
	@Autowired
	UserDao userDao;
	private static final int SUCCESS = 1;
	private static final int FAIL = -1;
	
	@Override
	public int followRegister(FollowDto followDto) {
		UserDto dto = userDao.userSelect(followDto.getReceiver());
		if(dto.getPublish() != SUCCESS)
			followDto.setType(2);
		else
			followDto.setType(SUCCESS);
		if(followDao.followRegister(followDto) == SUCCESS)
			return SUCCESS;
		else
			return FAIL;
	}

	@Override
	public  List<UserDto>  followSelect(int no) {
		List<UserDto> list = null;
		list = followDao.followSelect(no);
		return list;
	}

	@Override
	public  List<UserDto> followingSelect(int no) {
		List<UserDto> list = null;
		list = followDao.followingSelect(no);
		return list;
	}

	@Override
	public int followDelete(FollowDto followDto) {
		if(followDao.followDelete(followDto) == SUCCESS)
			return SUCCESS;
		else
			return FAIL;
	}

	@Override
	public int followUpdate(FollowDto followDto) {
		followDto.setType(1);
		if(followDao.followUpdate(followDto) == SUCCESS)
			return SUCCESS;
		else
			return FAIL;
	}

	@Override
	public FollowResultDto select(int sender, int receiver) {
		FollowResultDto followResultDto  = new FollowResultDto();
		FollowDto followDto = followDao.select(sender, receiver);
		
		if(followDto != null) {
			if(followDto.getType() == SUCCESS)
				followResultDto.setFollowResult(SUCCESS);
			else
				followResultDto.setWaition(SUCCESS);
		}
		List<UserDto> follower = followDao.followSelect(receiver);
		List<UserDto> following =  followDao.followingSelect(receiver);
		followResultDto.setFollower(follower);
		followResultDto.setFollowing(following);
		return followResultDto;
	}

}
