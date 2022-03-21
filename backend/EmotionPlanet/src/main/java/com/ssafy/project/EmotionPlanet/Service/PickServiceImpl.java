package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dao.PickContentDao;
import com.ssafy.project.EmotionPlanet.Dao.PickDao;
import com.ssafy.project.EmotionPlanet.Dao.S3Dao;
import com.ssafy.project.EmotionPlanet.Dto.ImgDto;
import com.ssafy.project.EmotionPlanet.Dto.PickContentDto;
import com.ssafy.project.EmotionPlanet.Dto.PickDto;
import com.ssafy.project.EmotionPlanet.Dto.S3Dto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class PickServiceImpl implements PickService{

    @Autowired
    PickDao pickDao;

    @Autowired
    PickContentDao pickContentDao;

    @Autowired
    S3Dao s3Dao;

    @Override
    public int create(PickDto pickDto) {


        return pickDao.create(pickDto);
    }

    @Override
    public List<PickDto> list(int userNo) {

        List<PickDto> pickDtos = pickDao.list(userNo);
        List<PickContentDto> pickContentDtos = new ArrayList<>();
        for (PickDto pickDto : pickDtos) {
            int pickNo = pickDto.getNo();
            int type = pickDto.getType();
            if (type == 0) {
                pickContentDtos = pickContentDao.listOnMusic(pickNo);
            } else if (type == 1) {
                pickContentDtos = pickContentDao.listOnMovie(pickNo);
            } else {
                pickContentDtos = pickContentDao.listOnActivity(pickNo);
            }
            pickDto.setContentsListData(pickContentDtos);
        }

        return pickDtos;
    }

    @Override
    public List<Integer> listOnNo(int userNo) {

        List<PickDto> pickDtos = pickDao.list(userNo);
        List<Integer> picksNo = new ArrayList<>();

        for (PickDto pickDto : pickDtos) {
            picksNo.add(pickDto.getNo());
        }
        return picksNo;
    }

    @Override
    public List<Integer> listByType(int userNo, int type) {
        List<PickDto> pickDtos = pickDao.listByType(userNo, type);
        List<Integer> picksNo = new ArrayList<>();

        for (PickDto pickDto : pickDtos) {
            picksNo.add(pickDto.getNo());
        }
        return picksNo;
    }

    @Override
    public PickDto select(int no, int userNo) {
        PickDto pickDto = pickDao.select(no);

        int like = pickDao.liking(userNo, pickDto.getNo());
        if(like != 0) pickDto.setLike(true);
        else pickDto.setLike(false);

        if(userNo == pickDto.getUserNo()) pickDto.setOwner(true);
        else pickDto.setOwner(false);

        int likes = pickDao.likes(pickDto.getNo());
        pickDto.setLikes(likes);

        int type = pickDto.getType();

        List<Integer> contentListNo = new ArrayList<>();
        List<PickContentDto> list = new ArrayList<>();
        if (type == 0) {
            List<PickContentDto> pickContentDtos = pickContentDao.listOnMusic(no);
            list = pickContentDtos;
            for (PickContentDto pickContentDto : pickContentDtos) {
                contentListNo.add(pickContentDto.getNo());
            }
        } else if (type == 1) {
            List<PickContentDto> pickContentDtos = pickContentDao.listOnMovie(no);
            list = pickContentDtos;
            for (PickContentDto pickContentDto : pickContentDtos) {
                contentListNo.add(pickContentDto.getNo());
            }
        } else {
            List<PickContentDto> pickContentDtos = pickContentDao.listOnActivity(no);
            list = pickContentDtos;
            for (PickContentDto pickContentDto : pickContentDtos) {
                contentListNo.add(pickContentDto.getNo());
            }
        }

        //pickDto.setContentsList(contentListNo);
        pickDto.setContentsListData(list);
        return pickDto;
    }

    @Override
    public int update(PickDto pickDto) {
//        S3Dto imgDto = s3Dao.selectByLink(pickDto.getImgLink());
//        s3Dao.deleteByNo(imgDto.getNo());
        return pickDao.update(pickDto);
    }

    @Override
    public int delete(int no) {
        PickDto pickDto = pickDao.select(no);
//        if(!("".equals(pickDto.getImgLink()) || pickDto.getImgLink() == null)) {
//            S3Dto imgDto = s3Dao.selectByLink(pickDto.getImgLink());
//            s3Dao.deleteByNo(imgDto.getNo());
//        }
        return pickDao.delete(no);
    }

    @Override
    public int like(int userNo, int pickNo) {
        return pickDao.like(userNo, pickNo);
    }

    @Override
    public int unlike(int userNo, int pickNo) {
        return pickDao.unlike(userNo, pickNo);
    }
}
