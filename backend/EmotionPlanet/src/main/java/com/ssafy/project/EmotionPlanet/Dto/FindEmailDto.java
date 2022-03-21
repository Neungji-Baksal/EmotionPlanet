package com.ssafy.project.EmotionPlanet.Dto;

public class FindEmailDto {
	private String email;
	private String tel;
	private String requestemail;
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getTel() {
		return tel;
	}
	public void setTel(String tel) {
		this.tel = tel;
	}
	public String getRequestemail() {
		return requestemail;
	}
	public void setRequestemail(String requestemail) {
		this.requestemail = requestemail;
	}
	public FindEmailDto() {}
	public FindEmailDto(String email, String tel, String requestemail) {
		super();
		this.email = email;
		this.tel = tel;
		this.requestemail = requestemail;
	}
	@Override
	public String toString() {
		return "FindEmailDto [email=" + email + ", tel=" + tel + ", requestemail=" + requestemail + "]";
	}
}
