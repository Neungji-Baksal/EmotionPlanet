<template>
	<div id="likes_list">
		<div id="modal">

      <div id="likes_list_header">

        <div id="title_container">
          <p id="title">추가하기 </p>
        </div>

        <div id="cancel">
          <i @click="goBack" class="fa-solid fa-x" style="font-size: 1.3rem; cursor: pointer;"></i>
        </div>

      </div>

      <hr>

      <div id="no_result" v-if="feedLikesList.length === 0">
        <img id="nothing" src="@/assets/images/etc/alien.png" alt="no result">
        <p id="no_likes">플레이리스트 목록이 없습니다...</p>
      </div>

      <div id="feed_likes_list" v-else>

        <div v-for="(liker, index) in feedLikesList" :key="index">

          <div id="userInfo">
            <img id="profile_img" :src="liker.profileImg" alt="">
            <p id="username">{{liker.nickname}}</p>
          </div>

        </div>

      </div>

      <hr>

      <div id="plus_container" v-if="isClick">
        <img id="plus_icon" @click="addList" src="@/assets/images/icons/more_selected.png" alt="">
        <p id="plus_text">새 플레이리스트 만들기</p>
      </div>

      <div id="new_container" v-else>
        <p id="plus_text">이름</p>
        <input id="playlist_input" @keyup.enter="inputName"  v-model.trim="listName" placeholder="플레이리스트 이름을 입력해주세요">

        <div id="uploading">
          <p id="plus_text">이미지 업로드</p>
          <input type="file" id="file" accept="image/*" @change="imgUpload" ref="feedImg"/>
        </div>

        <button id="pu_button" @click="createList">만들기</button>
      </div>

    </div>

  </div>
</template>

<script>
import axios from 'axios'
const session = window.sessionStorage;
const userdata = JSON.parse(session.getItem('userInfo')) ;
export default {
	data () {
		return {
			feedLikesList: [],//좋아요 누른 사람 목록
      isClick:true,
      images:null,
      listName:'',
      data:{
        name:'',//플레이리스트 이름
        type:this.$store.state.type,//음악 :0 영화:1 활동:2
        tagNo:userdata.tags[0]//행성
      }
		
		}
	},
	methods: {
    inputName:function(){
      this.data['name']=this.listName
    },
		goBack: function () {
			this.$store.commit('addPlayListActive',this.type)
      this.isClick=true
		},
    addList:function(){
      this.isClick=false
      console.log('여기')
      console.log(this.isClick)

    },
    imgUpload() {
      this.images = null;
      this.images = URL.createObjectURL(this.$refs.feedImg.files[0]);
    },
    createList:function () {
      if(this.listName){

        let headers = {
          'Content-Type': 'multipart/form-data',
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
  
        const formData2 = new FormData();
        this.Feedimages.forEach((file) => formData2.append("multipartFile", file.image));
        this.Feedimages.forEach((file) => console.log(file));
        formData2.append(
          "data",
          new Blob([JSON.stringify(this.data)], { type: "application/json" })
        );
  
        axios({
          method: 'put',
          url: '/api/picks',
          data: formData2, // post 나 put에 데이터 넣어 줄때
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
            console.log("피드 작성 : " + res.data)
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            this.isClick=true
        }).catch((error) => {
          console.log(error);
        }).then(() => {
          console.log('플레이리스트 생성하기');
        });
      }
      else{
        alert('제목을 입력해주세요')
      }
    },
	},
	destroyed () {
		this.feedLikesList = this.$store.state.feedLikesInfo
    console.log('여기입니다')
    console.log(this.isClick)
    // this.isClick=true
	}
}
</script>

<style>

</style>