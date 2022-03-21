package com.ssafy.project.EmotionPlanet.Dao;

import com.ssafy.project.EmotionPlanet.Dto.PickContentDto;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface PickContentDao {

    public List<PickContentDto> listOnMusic(int pickNo);
    public List<PickContentDto> listOnMovie(int pickNo);
    public List<PickContentDto> listOnActivity(int pickNo);

    public PickContentDto selectOnMusic(int no);
    public PickContentDto selectOnMovie(int no);
    public PickContentDto selectOnActivity(int no);

    public int createOnMusic(PickContentDto pickContentDto);
    public int createOnMovie(PickContentDto pickContentDto);
    public int createOnActivity(PickContentDto pickContentDto);

    public int deleteOnMusic(int no);
    public int deleteOnMovie(int no);
    public int deleteOnActivity(int no);
}
