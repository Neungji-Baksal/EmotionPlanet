package com.ssafy.project.EmotionPlanet.Dto;

import java.util.List;

public class UserRequestDto {

    private int no;
    private String nickname;
    private String profileImg;

    private UserSecretDto userInfo;

    public UserRequestDto() {
    }

    public UserRequestDto(int no, String nickname, String profileImg) {
        this.no = no;
        this.nickname = nickname;
        this.profileImg = profileImg;
    }

    public UserRequestDto(int no, String nickname, String profileImg, UserSecretDto userInfo) {
        this.no = no;
        this.nickname = nickname;
        this.profileImg = profileImg;
        this.userInfo = userInfo;
    }

    public int getNo() {
        return no;
    }

    public void setNo(int no) {
        this.no = no;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public String getProfileImg() {
        return profileImg;
    }

    public void setProfileImg(String profileImg) {
        this.profileImg = profileImg;
    }

    public UserSecretDto getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(UserSecretDto userInfo) {
        this.userInfo = userInfo;
    }

    @Override
    public String toString() {
        return "UserSecretDto{" +
                "no=" + no +
                ", nickname='" + nickname + '\'' +
                ", profileImg='" + profileImg + '\'' +
                ", userInfo=" + userInfo.toString() +
                '}';
    }
}
