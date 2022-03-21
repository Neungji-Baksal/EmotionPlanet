package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dto.ImgDto;

import java.util.List;

public interface ImgService {

    public List<ImgDto> list(int feedNo);

    public ImgDto select(int no);
}
