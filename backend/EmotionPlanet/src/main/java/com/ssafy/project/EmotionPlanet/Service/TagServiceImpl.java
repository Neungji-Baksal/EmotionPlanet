package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dao.TagDao;
import com.ssafy.project.EmotionPlanet.Dto.TagDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TagServiceImpl implements TagService{

    @Autowired
    TagDao tagDao;

    @Override
    public int create(TagDto tagDto) {

        TagDto duplicate = tagDao.duplicateTag(tagDto.getName());

        if(duplicate == null) {

            int result = tagDao.create(tagDto);
            if (result == 1) {
                int tagNo = tagDto.getNo();
                int feedNo = tagDto.getFeedNo();
                return tagDao.relation(tagNo, feedNo);
            } else return result;

        } else {
            int tagNo = duplicate.getNo();
            int feedNo = tagDto.getFeedNo();
            return tagDao.relation(tagNo, feedNo);
        }

    }

    @Override
    public TagDto select(int no) {
        return tagDao.select(no);
    }

    @Override
    public List<TagDto> list(int feedNo) {
        return tagDao.list(feedNo);
    }

}
