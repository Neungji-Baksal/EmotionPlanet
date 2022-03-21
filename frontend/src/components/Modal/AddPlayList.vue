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
    <div id="no_result" v-if="forderlists.length === 0">
      <img id="nothing" src="@/assets/images/etc/alien.png" alt="no result">
      <p id="no_likes">플레이리스트 목록이 없습니다...</p>
    </div>
    <div id="feed_likes_list" v-else>
      <div v-for="(forder, index) in forderlists" :key="index">
        <div id="userInfo">
          <p id="username">{{forder.name}}</p>
          <button id="follow_cancel" @click="choiceForder(forder)">찜하기</button>
          <img id="trash"  @click="deleteForder(forder.no)" src="@/assets/images/icons/trash.png" style="margin-right:1rem" alt="">
        </div>
      </div>
    </div>
    <hr id="footer">
    <div id="plus_container" v-if="isClick">
      <img id="plus_icon" @click="addList" src="@/assets/images/icons/more_selected.png" alt="">
      <p id="plus_text">새 플레이리스트 만들기</p>
    </div>
    <div id="new_container" v-else>
      <p id="plus_text">이름</p>
      <input id="playlist_input"  @keyup.enter="createList" v-model.trim="listName" placeholder="플레이리스트 이름을 입력해주세요">
      <button id="pu_button" @click="createList">만들기</button>
    </div>
  </div>
</div>
</template>

<script>
import axios from 'axios'
const session = window.sessionStorage;
export default {
	data () {
		return {
			feedLikesList: [],//좋아요 누른 사람 목록
      isClick:true,
      images:null,
      listName:'',
      listData:{
        name:'',//플레이리스트 이름
        type:null,//음악 :0 영화:1 활동:2
        tagNo:null,//행성
        userNo:null,
      },
      forderlistsNo:[],
      forderlists:[],
      pickNo:null,
      userdata:null,
      choicedForder:null,
      item:null,
		}
	},
	methods: {
    //퐇더 선택하기
    choiceForder:function(forder){
      this.choicedForder=forder.no
      this.pickedForder=forder.name
      let sendData=null
      if (this.listData.type==0){
         sendData={
          pickNo:this.choicedForder,
          author:this.item.artist,
          title:this.item.title,
          year:this.item.year,
          imgLink:this.item.imgLink,
          type:this.listData.type
        }
      }else if(this.listData.type==1){
        sendData={
          pickNo:this.choicedForder,
          targetNo:this.item.no,
          type:this.listData.type
        }
      }else{
        sendData={
          pickNo:this.choicedForder,
          targetNo:this.item.no,
          type:this.listData.type
        }
      }
      let headers = {
          // 'Content-Type': 'multipart/form-data',
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        axios({
          method: 'post',
          url: `/api/pickContent`,
          data:sendData,
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            this.$store.commit('addToPlayListActive',forder.name)
        }).catch((error) => {
          console.log(error);
        }).then(() => {
          console.log('플레이리스트에 담기');
        });
    },
    //폴더 삭제하기
    deleteForder:function(forderNo){
      let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        axios({
          method: 'delete',
          url: `/api/picks/${forderNo}`,
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            this.getPlayLists()
        }).catch((error) => {
          console.log(error);
        }).then(() => {
          console.log('플레이리스트 삭제');
        });
    },
    //창닫기
		goBack: function () {
			this.$store.commit('addPlayListActive',this.type)
      this.isClick=true
		},
    //폴더추가버튼
    addList:function(){
      this.isClick=false
    },
    //플레이리스트 데이터 가져오기
    getPlayList:function(){
      let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        axios({
          method: 'get',
          url: `/api/pick/${this.pickNo}`,
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            this.forderlists.push(res.data)
        }).catch((error) => {
          console.log(error);
        }).then(() => {
          console.log('플레이리스트 정보 가져오기');
        });
    },
    //유저 플레이리스트들 번호 가져오기
    getPlayLists:function(){
       let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };

        axios({
          method: 'get',
          url: `/api/picks/type/returnNo/${this.userdata.no}/${this.listData.type}`,
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            this.forderlistsNo=res.data
            this.forderlists=[]
            for(let i=0; i<this.forderlistsNo.length; i++){
              this.pickNo=this.forderlistsNo[i]
              this.getPlayList()
            }
        }).catch((error) => {
          console.log(error);
        }).then(() => {
          console.log('플레이리스트번호 목록 가져오기');
        });

    },
    //플레이리스트 만들기
    createList:function () {
      this.listData['name']=this.listName
      if(this.listName){

        let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
  
        const formData2 = new FormData();
        formData2.append(
          "data",
          new Blob([JSON.stringify(this.listData)], { type: "application/json" })
        );

        axios({
          method: 'post',
          url: '/api/picks',
          data: formData2, // post 나 put에 데이터 넣어 줄때
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            this.isClick=true
            this.getPlayLists()
            this.listName=''
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
	created () {
    this.userdata=JSON.parse(session.getItem('userInfo')) 
		this.feedLikesList = this.$store.state.feedLikesInfo
    this.listData['type']=this.$store.state.type
    this.item=this.$store.state.item
    this.listData['tagNo']=this.userdata.mood
    this.listData['userNo']=this.userdata.no
    this.getPlayLists()
	}
}
</script>

<style scoped>
#trash{
  width: 25px;
  height: 25px;
  cursor: pointer;
}
#check_img{
  width:25px;
  height: 25px;
  cursor: pointer;
}
#check_alert{
  margin-left: 1rem;
  color: gray;
}
#likes_list {
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
	background-color: white;
	border-radius: 20px;
	width: 25vw;
	min-width: 350px;
	min-height: 450px;
}
#likes_list_header {
	display: flex;
	flex-direction: row;
	justify-content: center;
	padding-top:1rem;
	padding-bottom: 1rem;
}
#title {
	margin-top: auto;
	margin-bottom: auto;
	font-size: 1.2rem;
	font-weight: bold;
}
#title_container{
	width: 58%;
	display: flex;
	justify-content: right;
}
#cancel {
	width: 42%;
	display: flex;
	justify-content: right;
	margin-right: 1rem;
	margin-top: 0.3rem;
}
#no_result {
	display:flex;
	flex-direction: column;
	align-items: center;
	margin-top: 25%;
	margin-bottom: 25%;
}
#nothing {
	width: 5rem;
	height: 5rem;
	margin-bottom: 0.5rem;
}
#no_likes {
	font-weight: bold;
}
#feed_likes_list{
	margin-left: 1rem;
	overflow-y: scroll;
	height: 20rem;
}
#userInfo{
	display: flex;
	flex-direction: row;
	margin-bottom:1rem;
	margin-top: 1rem;
}

#profile_img {
	width: 2rem;
	height: 2rem;
	border-radius: 50%;
	margin-right: 0.5rem;
	margin-top: auto;
	margin-bottom: auto;
}
#username {
	font-weight: bold;
	margin-right: 0.5rem;
	margin-top: auto;
	margin-bottom: auto;
}
#following_check{
	color: blue;
	font-size: 0.8rem;
	margin-top: auto;
	margin-bottom: auto;
}
#follow_cancel{
	margin-right: 0.5rem;
	margin-left: auto;
	margin-top: auto;
	margin-bottom: auto;
	background-color: #5E39B3;
	color: white;
	border-radius: 10px;
	font-size: 0.8rem;
	padding: 0.1rem;
}
hr {
	margin: 0;
}
#new_container{
  margin-left: 6%;
  margin-top: 0.5rem;
	width: 100%;
}
#plus_container{
  margin-top: 0.5rem;
  display: flex;
	width: 100%;
}
#plus_text{
	margin-top:auto;
	margin-bottom: auto; 
	margin-right: auto;
	font-size: 1.2rem;
	font-weight: bold;
}
#plus_icon{
	margin-left: auto;
	width: 50px;
	height: 50px;
	padding: 10px;
  cursor: pointer;
}
input:focus {
    outline-color: #5E39B3;
  }
#playlist_input{
  border-radius: 10px;
  padding: 0.3rem;
  margin-top:0.1rem;
}
#pu_button {
  background-color: #5E39B3;
  color: white;
  font-size: 1.125rem;
  font-weight: bold;
  border: none;
  border-radius: 20px;
  padding: 0.4rem 1.5rem;
  margin: 1rem 2rem 1rem 0;
  cursor: pointer;
  line-height: 2rem;
  margin-left: 60%;
}


</style>