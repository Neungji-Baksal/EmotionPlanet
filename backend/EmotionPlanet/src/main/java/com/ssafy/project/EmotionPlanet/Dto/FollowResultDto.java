package com.ssafy.project.EmotionPlanet.Dto;

import java.util.List;

public class FollowResultDto {
	private int followResult; // 0이면 언팔 1이면 팔로우중
	private int waition; // 1이면 대기중 
	private List<UserDto> follower;
	private List<UserDto> following;
	public int getFollowResult() {
		return followResult;
	}
	public void setFollowResult(int followResult) {
		this.followResult = followResult;
	}
	public int getWaition() {
		return waition;
	}
	public void setWaition(int waition) {
		this.waition = waition;
	}
	public List<UserDto> getFollower() {
		return follower;
	}
	public void setFollower(List<UserDto> follower) {
		this.follower = follower;
	}
	public List<UserDto> getFollowing() {
		return following;
	}
	public void setFollowing(List<UserDto> following) {
		this.following = following;
	}
	public FollowResultDto() {}
	public FollowResultDto(int followResult, int waition, List<UserDto> follower, List<UserDto> following) {
		super();
		this.followResult = followResult;
		this.waition = waition;
		this.follower = follower;
		this.following = following;
	}
	@Override
	public String toString() {
		return "FollowResultDto [followResult=" + followResult + ", waition=" + waition + ", follower=" + follower
				+ ", following=" + following + "]";
	}
	
}
