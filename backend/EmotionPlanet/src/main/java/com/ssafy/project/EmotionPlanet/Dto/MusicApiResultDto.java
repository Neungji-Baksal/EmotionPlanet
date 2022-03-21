package com.ssafy.project.EmotionPlanet.Dto;
import java.util.List;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@ToString
@Getter
@NoArgsConstructor

public class MusicApiResultDto {
	private List<tracks> track;
	
	@Getter
	@NoArgsConstructor
	@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
	public class tracks{
		
		@Getter
		@NoArgsConstructor
		public class Album{
			private List<Artists> artists;
			private List<Images> images;
			private String name;
			private String release_date;
			
			@Getter
			@NoArgsConstructor
			public class Artists{
				private String name;
			}
			
			@Getter
			@NoArgsConstructor
			public class Images{
				private String url;
			}
		}
	}
}
