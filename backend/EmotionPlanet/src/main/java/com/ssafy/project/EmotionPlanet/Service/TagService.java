package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dto.TagDto;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface TagService {

    public int create(TagDto tagDto);

    public TagDto select(int no);

    public List<TagDto> list(int feedNo);
}
