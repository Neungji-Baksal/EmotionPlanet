<template>
  <div id="feed" v-if="feed">
    <div id=" feed_innercontainer" style="width:95%; margin:auto;">
      <div id="header">
        <img id="profile_image" :src="feed.authorDetail.profileImg" />
        <div id="profile_content">
          <p id="username">{{feed.authorDetail.nickname}}</p>
          <p id="feed_date">{{ feed.date|dateChanger }}</p>
        </div>
      </div>
      <div id="post_image">
        <article id="img-box">
        <div id="uploaded-box">
            <transition-group id="carousel" :name="page > beforePage ? 'slide':'slide-reverse'">
              <img id="my_img" v-for="(image, index) in feed.imgs" :key="index"
              class="uploadedImg" :src="image.imgLink" alt=""
              v-show="index+1 == page">
            </transition-group>
            <div id="pages">
              <!-- <span v-for="idx in feed.imgs.length" :key="idx" 
              :class="['page-num', {'here':idx==page}]" @click="paginationByDot(idx)" /> -->
              <span v-for="idx in feed.imgs.length" :key="idx" 
              :class="['page-num', {'here':idx==page}]" />
            </div>
            <span id="left" class="carousel-btn" @click="pagination(false)"/>
            <span id="right" class="carousel-btn" @click="pagination(true)"/>
          </div>
        </article>
      </div>
      <div id="like">
        <div id="heart">
          <i class="far fa-heart fa-lg" style="cursor: pointer;"  :class="{'fas': this.feed.like}"  @click="like"></i>
        </div>
        <p id="feed_likes" v-for="(like, idx) in feed.likes" :key="idx"></p>
        <p class="likes" style="cursor: pointer;"  @click="likesList"  >{{feed.likes.length}} likes</p>
      </div>
      <div id="content">
        <div id="tag" style="flex-wrap: wrap;">
          <!-- <p id="my_tag">#{{feed.tags[0].name}}행성 <img :src="require('@/assets/images/emotions/' + tmp.img)" alt="" style="width: 1.2rem; height: 1.2rem;"> &nbsp;</p>  -->
          <p id="my_tag" v-for="(tag, idx) in feed.tags.slice(1)" :key="idx" style="flex-wrap: wrap;">#{{tag["name"]}} &nbsp;</p>
        </div> 
        <div v-if="isLong">
          <div v-if="isMore">
            <p id="caption" style="font-size:1.4rem; font-weight: bold; margin-right: 0.5rem; margin-top: auto; margin-bottom: auto;">{{feed.authorDetail.nickname}}</p>
            <p style="font-size: 1.2rem; margin: 0.3rem;">{{feed.descr}}</p>
          </div>
          <div id="user_caption" v-else>
            <p id="caption" style="font-size:1.4rem; font-weight: bold; margin-right: 0.5rem; margin-top: auto; margin-bottom: auto;">{{feed.authorDetail.nickname}}</p>
            <p id="caption-more" @click="captionMore">더보기</p>
          </div>
        </div>
        <div id="user_caption" v-else>
           <p id="caption" style="font-size:1.4rem; font-weight: bold; margin-right: 0.5rem; margin-top: auto; margin-bottom: auto;">{{feed.authorDetail.nickname}}</p>
          <p id="caption-more"> {{feed.descr}}</p>
        </div>
      </div>
      <comment-list :feedNo="post" :feedAuthor="feed.author" @delete-comment="commentKey++" :key="commentKey"></comment-list>
    </div>
  </div>
</template>

<script>
import CommentList from './CommentList.vue';
import axios from 'axios';
const session = window.sessionStorage;

export default {
  components: { CommentList },
  name: "Feed",
  props: {
    post: Number,
  },
  data(){
    return{
      page:1,
      beforePage:1,
      isCommentSettingOpened:false,
      isUserFeedSettingOpened: false,
      isMine:false,
      feed:null,
      isLong: false,
      isMore: false,
      posts:[],
      planetStyles: [
        { id: 1, name: '행복행성', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울행성', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#C5D3DC' },
        { id: 4, name: '공포행성', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝행성', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노행성', img: "rage.png", color: '#FB5D38' },
        { id: 7, name: '떠돌이행성', img: "spaceship.png", color: '#FCBB74' }
      ],
      commentKey: 0,
      // style: null,
    }
  },
  computed: {
    tmp: function () {
      let name = this.feed.tags[0]
      console.log(this.feed)
      let style = this.planetStyles.find(el => el.name === name) || {}
      console.log('이것은 스타일', style)
      return style
    }
  },
  methods: {
    pagination(payload){
      this.beforePage = this.page
      if (this.page < this.feed.imgs.length && payload){
        this.page ++
      }
      else if (this.page > 1 && !payload){
        this.page --
      }
    },
    // paginationByDot(target){
    //   let d
    //   if (target > this.page){
    //     d = true
    //   }
    //   else {
    //     d = false
    //   }
    //   for (let i=0;i<Math.abs(target-this.page);i++){
    //     setTimeout(() => {
    //       console.log(this.page, target, d)
    //       this.pagination(d)
    //     }, 1000 * i);
    //   }
    //},
    captionMore:function(){
      this.isMore=true

    },
    onCommentSetting:function(){
      this.$store.commit('commentSettingModalActivate')
    },

    onUserFeedSetting:function(){
      this.$store.commit('userFeedSettingModalActivate')
    },
    like:function(){
      this.feed.like ? this.cancelLike(): this.doLike();
      this.feed.like= !this.feed.like;
    },
    doLike:function(){
      let el = {
        receiver : this.feed.author,
        feedno : this.post,
      }
      this.$store.dispatch('addfeedlike',el)
      this.getFeed()
    },
    cancelLike:function(){
      this.$store.dispatch('deletefeedlike',this.post)
      this.getFeed()
    },
    getFeed:function(){
       let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        axios({
            method: 'get',
            url:`/api/feed/${this.post}`,
            headers: headers,  // 넣는거 까먹지 마세요
          }).then((res) => {
          this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
          console.log('!!!!!!!!!!!!!!!!!!!')
          console.log(res.data)
          this.feed=res.data
        
          if (this.feed.descr.length > 30) {
            this.isLong = true
          }
          }).catch((error) => {
            console.log(error);
          }).then(() => {
            console.log('피드 하나 가져오기');
          });
    },
    likesList:function(){
       this.$store.commit('likesListActive',this.feed.likes)
       console.log(this.feed.likes)
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
  created(){
   this.getFeed()
   console.log('몰라 알수가 업없어', this.tmp)
    
  }
  
};
</script>

<style scoped>
  
  .fas{
    color: crimson;
  }
  #setting{
    font-size: 2rem;
    margin-left: auto;
  }
  #content{
    text-align: left;
    margin:0rem 1rem;
    font-size: 1.2rem;
  }
  #tag{
    display:flex;
  }
  #like{
    display:flex;
    /* margin:0rem 3rem 0rem; */
    margin-left: 1rem;
    align-items: center;
    height: 3rem;

  }
  .likes{
    margin-top:1rem;
    margin-left:5px;
    font-size: 1.2rem;
  }
  #profile_content{
    direction:column;
  }
  #feed{
    border-bottom: 2px solid  gainsboro;
    margin-top:1rem;
    margin-bottom: 1rem;
    width: 100%;
  }

  #my_tag{
    color:rgb(37, 37, 201);
    margin-top: auto;
    margin-bottom:auto;
    font-size:1.2rem;
  }
  #header{
    display:flex;
    margin:1rem 1rem; 
  }
  #username{
    font-size: 2rem;
    font-weight: bold;
    margin: 0rem;
  }
  #feed_date {
    font-size: 1rem;
    margin-top: auto;
    margin-bottom: auto;
  }
  #profile_image{
    width: 5rem;
    height: 5rem;
    border-radius: 70%;
    margin-right: 0.5rem;
  }
  #my_img{
    width: 100%;
    height: 100%;
  }
  #post_image{
    position: relative;
    /* overflow: hidden; */
    display: flex;
    justify-content: center;
    align-items: flex-end;
    margin: auto;
    width: 98%;
  }
  .overlay_content {
    position: absolute;
    padding: 0rem 1rem;
    margin-right:16rem;
    background-color: white;
    border-radius: 10px;
  }
  #detail{
    width: 8%;
    font-size: 20px;
    border:1px solid black;
    border-radius: 10px;
    text-align: center;
    display: flex;
    flex-direction:column;
    position: absolute;
    /* transform: translate(34rem,-10px); */
    background-color: white;
  }
  #uploaded-box {
    width: 100%;
    height: 100%;
    position: relative;
  }
  
  .uploadedImg {
    width: 100%;
    /* aspect-ratio: 1/1;
    position: absolute; */
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
    display: flex;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: center;
    /* margin: 1rem; */
  }

  .page-num {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background-color: #cccccc;
    margin: 0.75rem;
    /* cursor: pointer; */
  }
   #img-box {
    width: 100%;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    margin-left: 1rem;
    margin-right: 1rem;
  }
  .here {
    background-color: #777777;
  }
  #left {
    background-image: url('../../../assets/images/icons/left.png');
    left: -2%;
  }

  #right {
    background-image: url('../../../assets/images/icons/right.png');
    right: -2%;
  }

  #carousel {
    display: flex;
    align-items: center;
    width: 100%;
    height: 100%;
    position: relative;
    overflow: hidden;
  }
  .carousel-btn {
    background-size: cover;
    border: none;
    border-radius: 50%;
    opacity: 0.75;
    position: absolute;
    width: 2rem;
    height: 2rem;
    top: 45%;
    cursor: pointer;
  }
  #user_caption{
    display: flex;
    flex-direction: row;
  }
  #caption-more {
    margin-top: auto;
    margin-bottom: auto;
  }
  #long_caption {
    display: flex;
  }
</style>