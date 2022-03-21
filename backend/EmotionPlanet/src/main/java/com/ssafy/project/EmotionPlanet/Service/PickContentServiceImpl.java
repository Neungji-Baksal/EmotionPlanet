package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dao.PickContentDao;
import com.ssafy.project.EmotionPlanet.Dao.PickDao;
import com.ssafy.project.EmotionPlanet.Dto.PickContentDto;
import com.ssafy.project.EmotionPlanet.Dto.PickDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class PickContentServiceImpl implements PickContentService{

    @Autowired
    PickContentDao pickContentDao;

    @Autowired
    PickDao pickDao;

    @Override
    public List<PickContentDto> list(int pickNo) {

        List<PickContentDto> list = new ArrayList<>();
        PickDto pickDto = pickDao.select(pickNo);
        int type = pickDto.getType();

        if (type == 0) {
            list = pickContentDao.listOnMusic(pickNo);
        } else if (type == 1) {
            list = pickContentDao.listOnMovie(pickNo);
        } else {
            list = pickContentDao.listOnActivity(pickNo);
        }
        System.out.println("dao 갯수 -----------" + list.size());
        return list;
    }

    @Override
    public PickContentDto select(int no) {
        PickDto pickDto = pickDao.select(no);
        int type = pickDto.getType();

        PickContentDto pickContentDto = new PickContentDto();

        if (type == 0) {
            pickContentDto = pickContentDao.selectOnMusic(no);
        } else if (type == 1) {
            pickContentDto = pickContentDao.selectOnMovie(no);
        } else {
            pickContentDto = pickContentDao.selectOnActivity(no);
        }

        return pickContentDto;
    }

    @Override
    public int create(PickContentDto pickContentDto) {

        int result = 0;
        int type = pickContentDto.getType();
        if (type == 0) {
            result = pickContentDao.createOnMusic(pickContentDto);
        } else if (type == 1) {
            result = pickContentDao.createOnMovie(pickContentDto);
        } else {
            result = pickContentDao.createOnActivity(pickContentDto);
        }

        return result;
    }

    @Override
    public int delete(PickContentDto pickContentDto) {
        int result = 0;
        int type = pickContentDto.getType();
        int no = pickContentDto.getNo();
        if (type == 0) {
            result = pickContentDao.deleteOnMusic(no);
        } else if (type == 1) {
            result = pickContentDao.deleteOnMovie(no);
        } else {
            result = pickContentDao.deleteOnActivity(no);
        }

        return result;
    }
}
