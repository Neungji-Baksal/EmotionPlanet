package com.ssafy.project.EmotionPlanet.Dto;

public class UserSecretDto {

    private int no;
    private String email;
    private String nickname;
    private String birth;
    private String profileImg;
    private String tel;
    private String intro;
    private int publish;
    private int mood;
    private int feedCount;


    @Override
    public String toString() {
        return "UserSecretDto{" +
                "no=" + no +
                ", email='" + email + '\'' +
                ", nickname='" + nickname + '\'' +
                ", birth='" + birth + '\'' +
                ", profileImg='" + profileImg + '\'' +
                ", tel='" + tel + '\'' +
                ", intro='" + intro + '\'' +
                ", publish='" + publish + '\'' +
                ", mood=" + mood +
                '}';
    }

    public UserSecretDto() {

    }

    public UserSecretDto(int no, String email, String nickname, String birth, String profileImg, String tel, String intro, int publish, int mood, int feedCount) {
        this.no = no;
        this.email = email;
        this.nickname = nickname;
        this.birth = birth;
        this.profileImg = profileImg;
        this.tel = tel;
        this.intro = intro;
        this.publish = publish;
        this.mood = mood;
        this.feedCount = feedCount;
    }

    public int getNo() {
        return no;
    }

    public void setNo(int no) {
        this.no = no;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public String getBirth() {
        return birth;
    }

    public void setBirth(String birth) {
        this.birth = birth;
    }

    public String getProfileImg() {
        return profileImg;
    }

    public void setProfileImg(String profileImg) {
        this.profileImg = profileImg;
    }

    public String getTel() {
        return tel;
    }

    public void setTel(String tel) {
        this.tel = tel;
    }

    public int getMood() {
        return mood;
    }

    public void setMood(int mood) {
        this.mood = mood;
    }

    public String getIntro() {
        return intro;
    }

    public void setIntro(String intro) {
        this.intro = intro;
    }

    public int getPublish() {
        return publish;
    }

    public void setPublish(int publish) {
        this.publish = publish;
    }

    public int getFeedCount() {
        return feedCount;
    }

    public void setFeedCount(int feedCount) {
        this.feedCount = feedCount;
    }
}
