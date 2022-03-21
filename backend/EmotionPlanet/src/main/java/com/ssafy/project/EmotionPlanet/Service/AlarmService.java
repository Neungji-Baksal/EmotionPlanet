package com.ssafy.project.EmotionPlanet.Service;

import java.util.List;

import com.ssafy.project.EmotionPlanet.Dto.AlarmDto;

public interface AlarmService {
	public AlarmDto insertAlram(AlarmDto alarmDto);
	public List<AlarmDto> selectAlram(int no);
	public int deleteAlram(int no);
	public int readanddeleteAlram(int receiver);
}