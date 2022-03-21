<template>
  <div id="profile_img_change_modal">
    <div id="modal">
      <div id="header">
        <img id="cancel" @click="cancel" src="@/assets/images/icons/return.png" alt="">
        <h3 id="header_title">프로필 사진 바꾸기</h3>
      </div>
      <hr id="hr">
      <div id="body">
        <div v-if="!images" id="thumbnail">
          <!-- 이미지 미리보기 만들어야 함 -->
          <img :src="this.$store.state.userInfo.profileImg" alt="" id="default-img">
        </div>
        <div v-else id="thumbnail">
          <img id="user_profile_img" :src="images" alt="" />
        </div>
      </div>
      <hr>
      <div id="footer">
        <div id="buttons">
          <div class="imgUpload">
            <label for="file">이미지 변경</label> 
            <input type="file" id="file" accept="image/*" @change="imgUpload" ref="feedImg" multiple>
          </div>
          <button id="changeImg" @click="changeprofileImg">확인</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from "axios";
const session = window.sessionStorage;
export default {
  data() {
    return {
      images: null,
    };
  },
  methods: {
    cancel: function () {
      this.$store.commit("profileImgChangeModalActivate");
    },
    imgUpload() {
      this.images = null;
      this.images = URL.createObjectURL(this.$refs.feedImg.files[0]);
      console.log(this.images)
    },
    changeprofileImg() {
      let headers = {
        "at-jwt-access-token": session.getItem("at-jwt-access-token"),
        "at-jwt-refresh-token": session.getItem("at-jwt-refresh-token"),
      };

      const formData = new FormData();
      formData.append("multipartFile", this.$refs.feedImg.files[0]);
      console.log(formData)

      axios({
        method: "post",
        url:
          "/api/s3/users/img/" + this.$store.state.userInfo.no,
        data: formData, // post 나 put에 데이터 넣어 줄때
        headers: headers, // 넣는거 까먹지 마세요
      })
        .then((res) => {
          console.log("이미지 변경 성공");
          console.log(res.data);
          this.$store.dispatch("allTokenRefreshOnUserInfo", res); // store아닌곳에서
          this.$store.state.userInfo.profileImg = this.images
          this.cancel()
          this.$router.go(-1)
        })
        .catch((error) => {
          console.log("이미지 변경 실패");
          console.log(error);
        });
    },
  },
};
</script>

<style scoped>

#profile_img_change_modal {
  display: flex;
  justify-content: center;
  align-items: center;
  width: 100%;
  height: 100%;
  background-color: rgb(0, 0, 0, 0.5);
  position: fixed;
  top: 0;
  left: 0;
  z-index: 999;
}
#modal {
  display: flex;
  flex-direction: column;
  align-items: center;
  background-color: white;
  border-radius: 30px;
  width: 30rem;
  height: 30rem;
  text-align: center;
  padding: 0.4rem;
}

#header {
  width: 100%;
  height: 10%;
  display: flex;
  flex-direction: row;
}
#cancel {
  width: 2rem;
  height: 2rem;
  margin-top: auto;
  margin-bottom: auto;
  margin-left: 0.4rem;
  cursor: pointer;
}
#header_title{
  margin-top: auto;
  margin-bottom: auto;
  margin-left: 6rem;
  font-weight: bold;
}
#body {
  width: 100%;
  height: 75%
}
#thumbnail {
  width: 100%;
  height: 100%;
}

#uploading {
  display: flex;
  width: 100%;
  height: 25%;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  border-top: 0.2rem solid gainsboro;
  border-bottom: 0.2rem solid gainsboro;
}

#default-img {
  width: 100%;
}

#changeImg {
  background-color: #5E39B3;
  color: white;
  font-size: 1.125rem;
  font-weight: bold;
  border: none;
  border-radius: 30px;
  padding: 0.3rem;
  margin-bottom: 1rem;
  width: 5rem;
  height: 2.8rem;
  margin: 1rem;
}
#footer {
  width: 100%;
  height: 15%;
}
#buttons {
  display: flex;
  justify-content: space-evenly;

}
hr {
  width: 100%;
  margin: 0rem;
  color: black;
}
.imgUpload label {
  background-color: #5E39B3;
  color: white;
  font-size: 1.125rem;
  font-weight: bold;
  border: 3px #5E39B3 solid;
  border-radius: 30px;
  padding: 0.2rem 1.5rem;
  margin: 1rem;
  cursor: pointer;
  line-height: 2rem;
}

.imgUpload input[type="file"] {
  position: absolute;
  width: 0;
  height: 0;
  padding: 0;
  overflow: hidden;
  border: 0;
}
img {
  width: 100%;
  height: 100%;
}
#user_profile_img {
  width: 100%;
  height: 100%;

}
</style>
