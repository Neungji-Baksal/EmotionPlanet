package com.ssafy.project.EmotionPlanet.Service;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ssafy.project.EmotionPlanet.Dao.AlarmDao;
import com.ssafy.project.EmotionPlanet.Dao.UserDao;
import com.ssafy.project.EmotionPlanet.Dto.AlarmDto;
import com.ssafy.project.EmotionPlanet.Dto.UserDto;

@Service
public class AlarmServiceImpl implements AlarmService {
	
	@Autowired
	AlarmDao alarmDao;
	
	@Autowired
	UserDao userDao;
	
	 private static final int SUCCESS = 1;
	 private static final int FAIL = 1;
	
	@Override
	public AlarmDto insertAlram(AlarmDto alarmDto) {
		Date date = new Date();
		TimeZone timeZone;
		timeZone = TimeZone.getTimeZone("Asia/Seoul");
		SimpleDateFormat format = new SimpleDateFormat ( "yyyy-MM-dd HH:mm:ss");
		format.setTimeZone(timeZone);
		alarmDto.setDate(format.format(date));
		int result = alarmDao.insertAlram(alarmDto);
		System.out.println(result);
		if(result >= SUCCESS)
			return alarmDto;
		return null;
	}

	@Override
	public List<AlarmDto> selectAlram(int no) {
		List<AlarmDto> list = alarmDao.selectAlram(no);
		System.out.println("알람 사이즈 : " + list.size());
		if(list.size() != 0)
			return list;
		return null;
	}

	@Override
	public int deleteAlram(int no) {
		int result = alarmDao.deleteAlram(no);
		if(result == SUCCESS)
			return SUCCESS;
		return FAIL;
	}

	@Override
	public int readanddeleteAlram(int receiver) {
		int result = alarmDao.updatereadAlram(receiver) + alarmDao.deleteAlramWeek(receiver);
		if(result >= SUCCESS)
			return SUCCESS;
		return FAIL;
	}
	
	

}
