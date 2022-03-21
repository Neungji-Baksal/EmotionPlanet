package com.ssafy.project.EmotionPlanet.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.ssafy.project.EmotionPlanet.Dto.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ssafy.project.EmotionPlanet.Dao.CommentDao;
import com.ssafy.project.EmotionPlanet.Dao.FeedDao;
import com.ssafy.project.EmotionPlanet.Dao.ImgDao;
import com.ssafy.project.EmotionPlanet.Dao.SearchDao;
import com.ssafy.project.EmotionPlanet.Dao.TagDao;
import com.ssafy.project.EmotionPlanet.Dao.UserDao;

@Service
public class SearchServiceImpl implements SearchService {

	@Autowired
	SearchDao searchDao;

	@Autowired
	FeedDao feedDao;

	@Autowired
	CommentDao commentDao;

	@Autowired
	TagDao tagDao;

	@Autowired
	ImgDao imgDao;
	
	@Autowired
	UserDao userDao;

	@Override
	public List<TagDto> tagSelect(String name) {
		List<TagDto> list = searchDao.tagSelect(name);
		if (list.size() == 0) {
			return null;
		} else {
			return list;
		}
	}

	@Override
	public List<FeedDto> tagfeedSelect(String name, int userNo) {
		List<Integer> taglist = searchDao.tagListSelect(name);
		List<FeedDto> list = new ArrayList<FeedDto>();
		if (taglist.size() != 0) {
			for (int no : taglist) {
				list.add(feedDao.read(no));
			}
			for (FeedDto feed : list) {
				List<CommentDto> comments = commentDao.list(feed.getNo());
				List<TagDto> tags = tagDao.list(feed.getNo());
				List<ImgDto> imgs = imgDao.list(feed.getNo());
				UserDto user = userDao.userSelect(feed.getAuthor());
				UserRequestDto userDetail = new UserRequestDto(user.getNo(), user.getNickname(), user.getProfileImg());
				if(userNo == feed.getAuthor()) feed.setOwner(true);
		        if(feedDao.liking(userNo, feed.getNo()) == 1) feed.setLike(true);
		        else feed.setLike(false);
		        feed.setComments(comments);
		        feed.setTags(tags);
		        feed.setImgs(imgs);
		        feed.setAuthorDetail(userDetail);
			}
			return list;
		} else {
			return null;			
		}
	}

	@Override
	public List<UserDto> userSelect(String name) {
		List<UserDto> list = searchDao.userSelect(name);
		if(list.size() != 0) {
			return list;
		}else {
		return null;
		}
	}

	@Override
	public List<Map<String, Object>> pickSelect(String name) {
		List<Map<String, Object>> list = searchDao.pickSelect(name);
		if (list.size() == 0) {
			return null;
		} else {
			return list;
		}
	}

	@Override
	public List<TagDto> picktagSelect() {
		List<TagDto> list = searchDao.picktagSelect();
		if (list.size() == 0) {
			return null;
		} else {
			return list;
		}
	}



//	@Override
//	public List<PickDto> recommendSelect(String name) {
//		List<PickDto> list = searchDao.recommendSelect(name);
//		if(list.size() != 0) {
//			for (PickDto pick : list) {
//				List<PickContentDto> pickcontents = searchDao.pickcontentSelect(pick.getNo());
//				//pick.setPickcontents(pickcontents);
//			}
//			return list;
//		}else {
//			return null;
//		}
//	}
}