<template>
  <div id="update_container">
    <div id="feed_detail">
      <div id="img_box">
        <transition-group id="carousel" :name="page > beforePage ? 'slide':'slide-reverse'">
          <img v-for="(image, index) in feedImages" :key="index"
          class="uploadedImg" :src="image.imgLink" alt=""
          v-show="index+1 == page">
        </transition-group>
        <div id="pages">
          <span v-for="idx in feedImages.length" :key="idx" 
          :class="['page-num', {'here':idx==page}]" />
        </div>
        <span id="left" class="carousel-btn1" @click="pagination(false)"/>
        <span id="right" class="carousel-btn2" @click="pagination(true)"/>
      </div>
      <div id="feed_text">
        <div id="text_head">
          <img id="profile_image" :src="userData.profileImg" alt="">
          <div id="profile_info">
            <p id="username">{{ userData.username }}</p>
            <p id="upload_date">{{ date|dateChanger }}</p>
          </div>
          <div id="cancel">
            <i @click="goBack" class="fa-solid fa-x" style="font-size: 1.3rem; cursor: pointer;"></i>
          </div>
        </div>
        <hr>
        <div id="text_body">
          <div id="tags">
            <div id="moodTag">
              <p id="pickTag" style="margin:auto 0.2rem; color: blue;"># {{feedData.tags[0].name}}행성<img :src="require('@/assets/images/emotions/' + tmp.img)" alt="" style="width: 1.2rem; height: 1.2rem; margin-left: 0rem;"></p>
            </div>
            <div id="actTag">
              <p id="pickTag" style="margin:auto 0.2rem; color: blue;"># {{feedData.tags[1].name}}</p>
            </div>
            <div v-if="feedData.tags.slice(2)">
              <div id="freeTag" v-for="(tag, idx) in feedData.tags.slice(2)" :key="idx"> 
                  <p id="pickTag" style="margin:auto 0.2rem; color: blue;">
                    # {{tag.name}}
                  </p>         
              </div>
            </div>
            <div v-else>
              <div id="freeTag" v-for="(tag, idx) in feedData.tags.slice(2)" :key="idx"> 
                  <p id="pickTag" style="margin:auto 0.2rem; color: blue; font-weight: bold;">
                    {{tag.name}}
                  </p>         
              </div>
            </div>
          </div>
          <br>
          <textarea rows="10" id="caption" v-model="feedData.descr" style="font-weight: bold;"></textarea>
        </div>
        <hr>
        <div id="feed_footer">
          <div class="imgUpload">
            <label for="file">이미지 업로드</label> 
            <input type="file" id="file" accept="image/*" @change="imgUpload" ref="feedImg" multiple>
          </div>
          <div>
            <button @click="feedUpdate">수정</button>
          </div>
        </div>
      </div>
    </div>
	</div>
</template>

<script>
import axios from 'axios'
import {mapState} from 'vuex'

const session = window.sessionStorage; 

export default {
	data: function () {
		return {
      page: 1,
      beforePage: 1,
      feedData: {
        descr: '',
        author: null,
        tags: [],
        no: null,
      },
      date: null,
      feedImages: [],
      userData: {
        username: null,
        profileImg: null,
      },
      planetStyles: [
        { id: 1, name: '행복', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이', img: "space-station.png", color: '#C5D3DC' },
        { id: 4, name: '공포', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노', img: "rage.png", color: '#FB5D38' },
      ],
		}
	},
	methods: {
    goBack: function () {
      this.$router.go({name: 'Main'})
    },
    imgUpload () {
      // this.$store.commit('feedImg', img)
      this.feedImages = []
      this.rawImage = this.$refs.feedImg.files;
      
      let num = -1;
      for (let i =0; i < this.$refs.feedImg.files.length; i++) {
        this.feedImages = [
          ...this.feedImages,
          {
            image: this.$refs.feedImg.files[i],
            imgLink: URL.createObjectURL(this.$refs.feedImg.files[i]),
            number: i
          }
        ];
        num = i;
      }
      this.uploadImageIndex = num + 1;

      if (this.feedImages.length > 3) {
        this.feedImages = []
        // alert('사진이 너무 많습니다')
        this.$store.commit('tooMuchImagesModalActivate')
      } else {
        this.$store.commit('feedImg', this.feedImages)
        this.$store.commit('rawImg', this.rawImage)
        // console.log('성공')
      }
    },
    feedUpdate () {
      let headers = {
        'Content-Type': 'multipart/form-data',
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
  
      console.log('이미지가 왜 없지', this.feedImages)
      const formData2 = new FormData();
      this.feedImages.forEach((file) => formData2.append("multipartFile", file.image));
      this.feedImages.forEach((file) => console.log(file));
      
      // 같은 사진을 한 번 더 사용할 경우를 체크
      // let cnt = 0
      // for (let value of formData2.values()) {
      //   if (typeof(value) == 'string')  {
      //     cnt++
      //   }
      // }
      // console.log(cnt)
      // console.log(this.feedImages.length)
      
      formData2.append(
        "userInfo",
        new Blob([JSON.stringify(this.feedData)], { type: "application/json" })
      );
      axios({
        method: 'put',
        url: '/api/feeds',
        data: formData2, // post 나 put에 데이터 넣어 줄때
        headers: headers,  // 넣는거 까먹지 마세요
      }).then((res) => {
          console.log("피드 작성 : " + res)
          this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
          // this.$router.go(0)
      }).catch((error) => {
        console.log(error);
      }).then(() => {
        console.log('getQSSList End!!');
      });

    },
    pagination(payload){
      this.beforePage = this.page
      if (this.page < this.feedImages.length && payload){
        this.page ++
      }
      else if (this.page > 1 && !payload){
        this.page --
      }
    },
    paginationByDot(target){
      let d
      if (target > this.page){
        d = true
      }
      else {
        d = false
      }
      for (let i=0;i<Math.abs(target-this.page);i++){
        setTimeout(() => {
          console.log(this.page, target, d)
          this.pagination(d)
        }, 1000 * i);
      }
    }
	},
  filters: {
    dateChanger(payload){
      const today = new Date();
      const timeValue = new Date(payload);

      const betweenTime = Math.floor((today.getTime() - timeValue.getTime()) / 1000 / 60);
      if (betweenTime < 1) return '방금전';
      if (betweenTime < 60) {
          return `${betweenTime}분전`;
      }

      const betweenTimeHour = Math.floor(betweenTime / 60);
      if (betweenTimeHour < 24) {
          return `${betweenTimeHour}시간전`;
      }

      const betweenTimeDay = Math.floor(betweenTime / 60 / 24);
      if (betweenTimeDay < 365) {
          return `${betweenTimeDay}일전`;
      }

      return `${Math.floor(betweenTimeDay / 365)}년전`;
    }
  },
  computed: {
    ...mapState([
      'feedDetailNum'
    ]),
    tmp: function () {
      let name = this.feedData.tags[0].name
      let style = this.planetStyles.find(el => el.name === name) || {}
      return style
    }
  },
  created () {
    this.feedData.no = this.feedDetailNum
    console.log(this.feedData.no)
    let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };

    axios({
      method: 'get',
      url: '/api/feed/' + this.feedData.no,
      headers: headers,  // 넣는거 까먹지 마세요
    }).then((res) => {
      console.log("피드 가져오기 : " + res.data)
      this.$store.dispatch('accessTokenRefresh', res) // store아닌곳
      this.feedData.descr = res.data.descr
      this.feedData.author = res.data.author
      console.log(this.feedData.author)
      this.feedData.tags = res.data.tags
      this.date = res.data.date
      console.log(this.date)
      this.feedImages = res.data.imgs
      this.userData.profileImg = res.data.authorDetail.profileImg
      this.userData.username = res.data.authorDetail.nickname
    }).catch((error) => {
      console.log(error);
    }).then(() => {
      console.log('getQSSList End!!');
    });
  },
}
</script>

<style scoped>
#update_container {
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
#feed_detail {
	width: 60rem;
	height: 43rem;
	display: flex;
	justify-content: center;
	align-items: center;
  margin: auto;
	border: 3px solid rgb(94, 57, 179);
  background-color: white;
}
#img_box {
  width: 70%;
  height: 100%;
  border-right: 2px solid gainsboro;
	border-left: none;
	border-top: none;
	border-bottom: none;
  position: relative;
}
#feed_text {
	height: 100%;
  width: 30%;
	display:flex;
	flex-direction: column;
}
#text_head {
	display: flex;
	flex-direction: row;
	justify-content: left;
	align-items: center;
	height: 8vh;
	margin-left: 1rem;
  margin-top: 0.5rem;
  margin-bottom: 0.4rem;
}
#profile_image {
	width: 4.5rem;
	height: 4.5rem;
	border-radius: 50%;
	margin-right: 0.5rem;
}
#profile_info {
	padding-top:auto;
	padding-bottom: auto;
}
#username {
	font-weight: bold;
	margin: 0rem;
	font-size: 1.4rem;
}
#upload_date {
	text-align: left;
	font-size: 1rem;
	margin: 0rem;
}
#cancel {
	margin-left:auto;
	margin-right: 1rem;
}
#text_body {
	height: 65vh;
	overflow: auto;
	margin-left: 0.4rem;
	margin-right: 0.4rem;
	margin-top: 0.5rem;
}
#caption {
  width: 100%;
  height: 85%;
	font-size: 1rem;
	text-align: left;
  resize:none;
  border: none;
}
#caption:focus {
  outline: none;
}
#tags {
	display: flex;
	flex-direction: row;
	flex-wrap: wrap;
}
#tag {
	color: rgb(46, 46, 255);
	font-size: 0.8rem;
}
hr{
  margin: 0rem;
  color: rgb(141, 140, 140);
  height: 2px;
}
#feed_footer {
  display: flex;
  flex-direction: row;
  justify-content: space-between;
  align-content: center;
}
.imgUpload label {
    background-color: #5E39B3;
    color: white;
    font-size: 1rem;
    font-weight: bold;
    border: 1px #5E39B3 solid;
    border-radius: 20px;
    padding: 0.3rem;
    margin: 1rem;
    cursor: pointer;
  }

.imgUpload input[type="file"] {
    position: absolute;
    width: 0;
    height: 0;
    padding: 0;
    overflow: hidden;
    border: 0;
}
button {
  color: white;
  font-weight: bold;
  border-radius: 20px;
  border: 1px #5E39B3 solid;
  background-color: #5E39B3;
  font-size: 1rem;
  text-align: center;
  width: 4rem;
  padding: 0.3rem;
  margin: 1rem;
}
#carousel {
  display: flex;
  align-items: center;
  width: 100%;
  height: 100%;
  position: relative;
  /* overflow: hidden; */
}
.uploadedImg {
  width: 100%;
	height: 100%;
	/* border-radius: 10px; */
  /* aspect-ratio: 1/1; */
}
.carousel-btn1 {
  background-size: cover;
  border: none;
  border-radius: 50%;
  opacity: 0.75;
  position: absolute;
  width: 2rem;
  height: 2rem;
  top: 312px;;
  cursor: pointer;
}
.carousel-btn2 {
  background-size: cover;
  border: none;
  border-radius: 50%;
  opacity: 0.75;
  position: absolute;
  width: 2rem;
  height: 2rem;
  top: 312px;
  cursor: pointer;
}

#left {
  background-image: url('../assets/images/icons/left.png');
  left:1px;
}

#right {
  background-image: url('../assets/images/icons/right.png');
  right: 1px;
}

@keyframes slide-in {
  from { right: -100% }
  to { right: 0 }
}

@keyframes slide-out {
  from { right: 0 }
  to { right: 100% }
}

.slide-enter-active {
  animation: slide-in 1s ease;
}

.slide-leave-active {
  animation: slide-out 1s ease;
}

.slide-reverse-enter-active {
  animation: slide-out 1s ease reverse;
}

.slide-reverse-leave-active {
  animation: slide-in 1s ease reverse;
}

#pages {
  position: absolute;
  top: 93%;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  flex-wrap: nowrap;
  justify-content: center;
  align-items: center;
  margin: 1rem;
}

.page-num {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background-color: #cccccc;
  margin: 0.75rem;
}

.here {
  background-color: #777777;
}
</style>