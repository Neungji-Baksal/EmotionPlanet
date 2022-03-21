<template>
  <div id="feed" v-if="feed">
    <div id="feed-header">
      <img id="profile-img" :src="feed.authorDetail.profileImg" />
      <div id="profile-content">
        <h2 id="author-name">{{ feed.authorDetail.nickname }}</h2>
        <p id="auth-date">{{ feed.date|dateChanger }}</p>
      </div>
    </div>

    <div id="img-box">
      <transition-group id="carousel" :name="page > beforePage ? 'slide':'slide-reverse'">
        <img v-for="(image, index) in feed.imgs" :key="index"
        class="feed-img" :src="image.imgLink" :alt="image.imgLink"
        v-show="index+1 == page">
      </transition-group>
      <div id="pages">
        <span v-for="idx in feed.imgs.length" :key="idx" 
        :class="['page-num', {'here':idx==page}]" @click="paginationByDot(idx)" />
      </div>
      <span id="left" class="carousel-btn" @click="pagination(false)"/>
      <span id="right" class="carousel-btn" @click="pagination(true)"/>
      <span id="overlay">
        <p>
          {{ feed.authorDetail.nickname}}님은 {{tmp.name}}
        </p>
        <img id="planet" :src="require('@/assets/images/emotions/' + tmp.img)">
        <p>에 있어요</p>
      </span>
    </div>

    <div id="feed-body">
      <div id="info">
        <i class="far fa-heart fa-lg" :class="{'fas': this.feed.like}" @click="like"></i>
        <p class="likes">{{feed.likes.length}} likes</p>
      </div>
      <div id="content">
        <div id="tags">
          <p v-for="(tag, idx) in feed.tags" :key="idx">#{{tag.name}}</p>
        </div> 
          <p id="descr">
            {{feed.descr}}
          </p>
      </div>
    </div>

    <comment-list :comments="feed.comments"></comment-list>
  </div>
</template>

<script>
import CommentList from '@/components/MainPage/FeedTab/CommentList.vue';
import axios from 'axios'

export default {
  components: { CommentList },
  name: "Feed",
  props: {
    idx: Number,
  },
  data(){
    return{
      feed:null,
      page: 1,
      beforePage: 1,
      planetStyles: [
        { id: 1, name: '행복행성', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울행성', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#C5D3DC' },
        { id: 4, name: '공포행성', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝행성', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노행성', img: "rage.png", color: '#FB5D38' },
      ]
    }
  },
   computed: {
    tmp: function () {
      const id = this.feed.tags[0].no
      const style = this.planetStyles.find(el => el.id === id) || {}
      return style
    }
  },
  methods: {
    onSetting:function(){
      if(this.isOpend){
        this.isOpend=false
      }else{
        this.isOpend=true
      }
    },
    like() {
      this.feed.like ? this.feed.likes-- : this.feed.likes++;
      this.feed.like= !this.feed.like;
    },
    pagination(payload){
      this.beforePage = this.page
      if (this.page < this.feed.imgs.length && payload){
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
  created(){
    const session = window.sessionStorage
    let headers = {
      'at-jwt-access-token': session.getItem('at-jwt-access-token'),
      'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
    };
    axios({
      method: 'get',
      url:`/api/feed/${this.idx}`,
      headers: headers,  // 넣는거 까먹지 마세요
    })
    .then((res) => {
      this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
      console.log('!!!!!!!!!!!!!!!!!!!')
      console.log(res.data)
      this.feed=res.data
    })
    .catch((error) => {
      console.log(error);
    })
  }
};
</script>

<style scoped>
  h2, p {
    margin: 0;
  }

  #feed{
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 90%;
    aspect-ratio: 1/1;
    border: 3px solid  rgb(94, 57, 179);
    border-radius: 20px;
    margin:1rem;
    padding: 1rem;
  }

  #feed-header {
    display: flex;
    align-items: center;
    align-self: flex-start;
  }

  #profile-img {
    width: 5rem;
    height: 5rem;
    border-radius: 50%;
    margin: 1rem;
  }

  #author-name {
    font-size: 1.75rem;
    font-weight: bold;
  }

  #auth-date {
    font-size: 1.125rem;
    color: #777777;
  }

  #img-box {
    width: 90%;
    height: 60%;
    position: relative;
    margin: 2rem 2rem 3rem;
  }

  #carousel {
    display: flex;
    align-items: center;
    width: 100%;
    height: 100%;
    position: relative;
    overflow: hidden;
    border-radius: 20px;
  }

  .feed-img {
    width: 100%;
    max-height: 100%;
    position: absolute;
  }

  .carousel-btn {
    background-size: cover;
    border: none;
    border-radius: 50%;
    opacity: 0.75;
    position: absolute;
    width: 8%;
    aspect-ratio: 1/1;
    top: 45%;
    cursor: pointer;
  }

  #left {
    background-image: url('../../assets/images/icons/left.png');
    left: -2%;
  }

  #right {
    background-image: url('../../assets/images/icons/right.png');
    right: -2%;
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
    margin: 1rem;
  }

  .page-num {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background-color: #cccccc;
    margin: 0.75rem;
    cursor: pointer;
  }

  .here {
    background-color: #777777;
  }

  #overlay {
    display: flex;
    align-items: center;
    background-color: white;
    border: 2px rgb(94, 57, 179) solid;
    border-radius: 20px;
    position: absolute;
    bottom: 5%;
    left: 5%;
    padding: 0.5rem 1rem;
  }

  #overlay p {
    font-size: 1.125rem;
    font-weight: bold;
  }

  #planet {
    width: 2rem;
    height: 2rem;
    margin: 0 0.25rem;
  }

  #feed-body {
    display: flex;
    flex-direction: column;
    width: 90%;
  }

  #info {
    display: flex;
    align-items: center;
  }

  #info * {
    font-size: 1.5rem;
    margin: 0.5rem;
  }

  #info p {
    font-weight: bold;
  }

  #content {
    display: flex;
    flex-direction: column;
    width: 100%;
  }

  #tags {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    width: 100%;
  }

  #tags p {
    color: rgb(85, 85, 255);
    font-size: 1.25rem;
    font-weight: bold;
    margin: 0 0.25rem;
  }

  #descr {
    font-size: 1.25rem;
  }
</style>