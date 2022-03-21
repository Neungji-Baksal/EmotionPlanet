package com.ssafy.project.EmotionPlanet.Dto;

public class FollowDto {
	private int sender;
	private int receiver;
	private int type; //0이면 대기중 1이면 이미 팔로우 완료  
	public int getSender() {
		return sender;
	}
	public void setSender(int sender) {
		this.sender = sender;
	}
	public int getReceiver() {
		return receiver;
	}
	public void setReceiver(int receiver) {
		this.receiver = receiver;
	}
	public int getType() {
		return type;
	}
	public void setType(int type) {
		this.type = type;
	}
	public FollowDto() {}
	public FollowDto(int sender, int receiver, int type) {
		super();
		this.sender = sender;
		this.receiver = receiver;
		this.type = type;
	}
	@Override
	public String toString() {
		return "FollowDto [sender=" + sender + ", receiver=" + receiver + ", type=" + type + "]";
	}
	
	
	
}
