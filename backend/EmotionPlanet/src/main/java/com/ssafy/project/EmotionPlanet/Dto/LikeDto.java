package com.ssafy.project.EmotionPlanet.Dto;

public class LikeDto {

    private int userNo;
    private int targetNo;

    public LikeDto() {
    }

    public int getUserNo() {
        return userNo;
    }

    public void setUserNo(int userNo) {
        this.userNo = userNo;
    }

    public int getTargetNo() {
        return targetNo;
    }

    public void setTargetNo(int targetNo) {
        this.targetNo = targetNo;
    }
}
