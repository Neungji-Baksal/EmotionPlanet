package com.ssafy.project.EmotionPlanet.Dao;

import com.ssafy.project.EmotionPlanet.Dto.ImgDto;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface ImgDao {

    public List<ImgDto> list(int relationNo);

    public ImgDto select(int no);

    public int relation(
            @Param("imgNo") int imgNo,
            @Param("feedNo") int feedNo);

    public int relationDelete(
            @Param("imgNo") int imgNo,
            @Param("feedNo") int feedNo);

}
