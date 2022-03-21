package com.ssafy.project.EmotionPlanet.Dao;

import com.ssafy.project.EmotionPlanet.Dto.PickDto;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface PickDao {
    public int create(PickDto pickDto);

    public List<PickDto> list(int userNo);

    public List<PickDto> listByType(
            @Param("userNo") int userNo,
            @Param("type") int type);

    public PickDto select(int no);

    public int update(PickDto pickDto);

    public int delete(int no);

    //map - @param

    public int likes(int pickNo);

    public int like(
            @Param("userNo") int userNo,
            @Param("pickNo") int pickNo);
    public int liking(
            @Param("userNo") int userNo,
            @Param("pickNo") int pickNo);
    public int unlike(
            @Param("userNo") int userNo,
            @Param("pickNo")int pickNo);

}
