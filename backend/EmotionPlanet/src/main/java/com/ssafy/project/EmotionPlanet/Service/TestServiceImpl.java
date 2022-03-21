package com.ssafy.project.EmotionPlanet.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ssafy.project.EmotionPlanet.Dao.TestDao;
import com.ssafy.project.EmotionPlanet.Dto.TestDto;

@Service
public class TestServiceImpl implements TestService {

	@Autowired
	TestDao testDao;

	List<TestDto> list;
	List<TestDto> happiness = new ArrayList<TestDto>();
	List<TestDto> depressed = new ArrayList<TestDto>();
	List<TestDto> neutrality = new ArrayList<TestDto>();
	List<TestDto> fear = new ArrayList<TestDto>();
	List<TestDto> surprise = new ArrayList<TestDto>();
	List<TestDto> anger = new ArrayList<TestDto>();
	TreeMap<Integer, Integer> map = new TreeMap<Integer, Integer>();
	
	@Override
	public List<TestDto> step1() { // 데이터 요청 호출
		list = new ArrayList<TestDto>(); // 최종 데이터 저장리스트 초기화
		happiness = testDao.select(1); // 각 카테고리 단어를 DB를 통해 리스트로 가져옴
		depressed = testDao.select(2);
		neutrality = testDao.select(3);
		fear = testDao.select(4);
		surprise = testDao.select(5);
		anger = testDao.select(6);
		random(list, happiness, 4, happiness.size()); // 리스트별로 랜덤 단어 4개를 뽑고 최종 데이터 저장리스트에 저장.
		random(list, depressed, 4, depressed.size());
		random(list, neutrality, 4, neutrality.size());
		random(list, fear, 4, fear.size());
		random(list, surprise, 4, surprise.size());
		random(list, anger, 4, anger.size());
		// 이름순으로 정렬 why? 현재 데이터는 카테고리별로 뭉쳐져있음 1~4: 1번카테고리 단어 , 2~8: 2번카테고리 단어....
		list.sort((a,b) -> a.getName().compareTo(b.getName())); 
		return list;
	}

	public void random(List<TestDto> list, List<TestDto> emt, int n, int m) { // 랜덤 단어를 4개 뽑고, 뽑은 단어는 기존 리스트에서 제거
		Random r = new Random();
		int number[] = new int[n];
		for (int i = 0; i < n; i++) {
			number[i] = r.nextInt(m);
			for (int j = 0; j < i; j++) {
				if (number[i] == number[j])
					i--;
			}
		}
		for (int i = 0; i < n; i++) {
			list.add(emt.get(number[i]));
		}
		Arrays.sort(number); // 정렬한 이유 : 중간 값을 빼버리면 리스트 뒤에 값이 앞당겨짐 즉 큰값부터 작은값순으로 제거하기 위해
		for (int i = n - 1; i >= 0; i--) {
			emt.remove(number[i]);
		}
	}

	@Override
	public List<TestDto> step2(List<TestDto> testDto) { // 1단계 테스트 결과를 통해 2단계 단어 추출
		list = new ArrayList<TestDto>(); // 최종 데이터 저장 리스트 초기화
		int score[] = { 6, 5, 4, 3, 2, 1 }; // 단어 순서별 점수
		int count[] = { 8, 6, 4, 3, 2, 1 }; // 단어 점수별 반환하는 단어 갯수 
		map = new TreeMap<Integer, Integer>();
		for (int i = 0; i < testDto.size(); i++) { //넘어온 데이터의 카테고리별 순서 점수 + 카드갯수 점수를 map를 이용해 받아온다.
			TestDto dto = testDto.get(i);
			map.put(dto.getType(), map.getOrDefault(dto.getType(), 0) + 1 + score[i]);
		}
		ArrayList<Map.Entry<Integer, Integer>> totalscore = new ArrayList<>(map.entrySet()); // map를 List로 변환 높은 점수순으로 정렬하기 위해
		totalscore.sort((a, b) -> map.get(b.getKey()) - map.get(a.getKey())); // 리스트를 map의 value값으로 정렬한다.
		System.out.println("첫 번째 결과 : "+ totalscore); 
		for (int i = 0; i < totalscore.size(); i++) { // 점수를 기준으로 각 카테고리별 단어를 몇개 뿌릴지 체크하여 최종 데이터 저장리스트에 담음
			switch (totalscore.get(i).getKey()) {
			case 1:
				random(list, happiness, count[i], happiness.size());
				break;
			case 2:
				random(list, depressed, count[i], depressed.size());
				break;
			case 3:
				random(list, neutrality, count[i], neutrality.size());
				break;
			case 4:
				random(list, fear, count[i], fear.size());
				break;
			case 5:
				random(list, surprise, count[i], surprise.size());
				break;
			case 6:
				random(list, anger, count[i], anger.size());
				break;
			}
		}
    	list.sort((a,b) -> a.getName().compareTo(b.getName())); //단어 이름순으로 정렬
		return list;
	}

	@Override
	public TestDto step3(List<TestDto> testDto) {
		for (int i = 0; i < testDto.size(); i++) { // 순서 점수 x 카드 갯수만 카운트
			TestDto dto = testDto.get(i);
			map.put(dto.getType(), map.getOrDefault(dto.getType(), 0) + 1); // 기존 점수에 갯수 카운트한걸 더해줌.
		}
		ArrayList<Map.Entry<Integer, Integer>> totalscore = new ArrayList<>(map.entrySet()); //정렬
		totalscore.sort((a, b) -> map.get(b.getKey()) - map.get(a.getKey())); //정렬
		System.out.println("마지막  결과 : "+ totalscore); 
		TestDto dto = new TestDto(); 
		
		switch (totalscore.get(0).getKey()) { //가장 앞에온 데이터 = 가장 점수가 높은 카테고리 => 리턴
		case 1:
			dto.setName("행복");
			break;
		case 2:
			dto.setName("우울");
			break;
		case 3:
			dto.setName("중립");
			break;
		case 4:
			dto.setName("공포");
			break;
		case 5:
			dto.setName("깜짝");
			break;
		case 6:
			dto.setName("분노");
			break;
		}
		dto.setNo(totalscore.get(0).getKey()); 
		return dto;
	}
}
