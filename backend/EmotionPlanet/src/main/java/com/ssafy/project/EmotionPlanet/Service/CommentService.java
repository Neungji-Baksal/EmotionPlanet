package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dto.CommentDto;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface CommentService {
    public List<CommentDto> list(int feedNo);
    public List<Integer> listOnNo(int feedNo);
    public CommentDto read(int no, int userNo);
    public int write(CommentDto commentDto);
    public int update(CommentDto commentDto);
    public int delete(int no);

}
