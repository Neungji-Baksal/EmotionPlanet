package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dto.FeedDto;
import com.ssafy.project.EmotionPlanet.Dto.UserRequestDto;
import org.springframework.stereotype.Service;

import java.util.List;

public interface FeedService {
    public List<FeedDto> list(int no);
    public List<Integer> listReturnNo(int no);
    public List<FeedDto> myList(int no, int userNo);
    public List<Integer> myListReturnNo(int no);
    public FeedDto read(int no, int userNo);
    public int write(FeedDto feedDto);
    public int update(FeedDto feedDto, int type);
    public int delete(int no);
    public List<UserRequestDto> likeList(int feedNo);
    public int like(int userNo, int feedNo);
    public int unlike(int userNo, int feedNo);
    public int connect(String targetNo, List<Integer> result);
}
