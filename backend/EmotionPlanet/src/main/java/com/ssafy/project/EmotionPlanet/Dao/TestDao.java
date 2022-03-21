package com.ssafy.project.EmotionPlanet.Dao;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import com.ssafy.project.EmotionPlanet.Dto.TestDto;

@Mapper
public interface TestDao {
    public List<TestDto> select(int no);
}
