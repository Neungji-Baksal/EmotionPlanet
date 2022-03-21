package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dao.ImgDao;
import com.ssafy.project.EmotionPlanet.Dto.ImgDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ImgServiceImpl implements ImgService{

    @Autowired
    ImgDao imgDao;


    @Override
    public List<ImgDto> list(int feedNo) {
        return imgDao.list(feedNo);
    }

    @Override
    public ImgDto select(int no) {
        return imgDao.select(no);
    }
}
