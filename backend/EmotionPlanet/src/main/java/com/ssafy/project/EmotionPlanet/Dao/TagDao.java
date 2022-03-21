package com.ssafy.project.EmotionPlanet.Dao;

import com.ssafy.project.EmotionPlanet.Dto.TagDto;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface TagDao {

    public int create(TagDto tagDto);

    public TagDto duplicateTag(String name);

    public TagDto select(int no);

    public List<TagDto> list(int feedNo);

    public int relation(
            @Param("tagNo") int tagNo,
            @Param("feedNo") int feedNo);

    public int deleteRelation(
            @Param("tagNo") int tagNo,
            @Param("feedNo") int feedNo);
}
