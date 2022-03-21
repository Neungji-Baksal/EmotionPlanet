package com.ssafy.project.EmotionPlanet.Dao;

import com.ssafy.project.EmotionPlanet.Dto.ImgDto;
import com.ssafy.project.EmotionPlanet.Dto.S3Dto;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Mapper
public interface S3Dao {
    public int flushFile(S3Dto s3Dto);
    public int updateimg(@Param(value = "no") int no,@Param(value = "imgLink") String imgLink);
    public void deleteFile(String imgName);
    public void deleteByNo(int imgName);
    public int select(String imgName);
    public S3Dto selectByLink(String imgLink);
}
