<template>
  <div class="card_container" v-show="isActive">
    <div class="card_header">
      <img id="profile_image" :src="this.$store.state.userInfo.profileImg" alt="">
      <span id="opacity"></span>
      <div class="overlay_content">
        <h2>{{ this.$store.state.userInfo.nickname }}</h2>
        <button id="update" @click="$router.push({name: 'Setting'})">프로필 수정</button>
      </div>
    </div>
    <div class="card_body">
      <p style="margin-top: auto; margin-bottom: auto;">이야기 {{ this.$store.state.userInfo.feedCount }}개</p>
      <p style="margin-top: auto; margin-bottom: auto;">팔로워 {{ this.$store.state.userFollowInfo.userFollow.length }}명</p>
      <p style="margin-top: auto; margin-bottom: auto;">팔로우 {{ this.$store.state.userFollowInfo.userFollowing.length }}명</p>
    </div>
    <div id="card_footer">
      <div id="where">
        <span style="font-size:1.3rem; font-weight:bold; margin-left:1.2rem;">나는 지금...</span>
        <span id="at">
          <img id="planet_img" :src="require('@/assets/images/emotions/' + tmp.img)">
          <p id="planet_name" style="font-size:1.5rem; font-weight:bold; margin-top:auto; margin-bottom: auto; margin-left:0.3rem" :style="{color:tmp.color}">{{tmp.name }} 여행 중</p>
        </span>
      </div>
      <div id="footer_buttons">
        <button id="feed_write" @click="createFeed">감정 공유하기</button>
        <button id="go_emotiontest" @click="$router.push({ name:'EmotionTest' })">다른 행성가기</button>
      </div>
    </div>  
  </div>  
</template>

<script>
export default {
  name: 'SideProfileCard',
  props: {
    userInfo: Object,
  },
  data() {
    return {
      planetStyles: [
        { id: 1, name: '행복행성', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울행성', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#ABBECA' },
        { id: 4, name: '공포행성', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝행성', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노행성', img: "rage.png", color: '#FB5D38' },
        { id: 7, name: '떠돌이행성', img: "spaceship.png", color: '#FCBB74' },
      ],
      isActive: false
    }
  },
  computed: {
    tmp: function () {
      const mood = this.$store.state.userInfo.mood
      const style = this.planetStyles.find(el => el.id === mood) || {}
      return style
    }
  },
   methods: {
    createFeed: function(){
      this.$store.commit('navActivate', 0)
    },
    resize(){
      window.innerWidth > 1400 ? this.isActive = true: this.isActive = false
    }
  },
  mounted(){
    if (window.innerWidth > 1400){
      this.isActive = true
    }
    window.addEventListener('resize', this.resize)
  }
}
</script>

<style scoped>
  .card_container {
    display: flex;
    flex-direction: column;
    width: 23rem;
    min-width: 300px;
    height: 32rem;
    min-height: 400px;
    position: fixed;
    top: 10rem;
    right: 2.5%;
    z-index: 1;
    border: 0.2rem solid gainsboro;
    border-radius: 10px;
  }

  .card_header {
    position: relative;
    overflow: hidden;
    display: flex;
    justify-content: center;
    align-items: flex-end;
    width: 100%;
    height: 50%;
    background-image: url('../assets/images/emotions/cover_s.png');
    background-repeat: no-repeat;
    background-position: center;
    background-size: cover;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
  }

  .overlay_content {
    position: absolute;
    display: flex;
    direction: row;
    width: 90%;
    justify-content: space-between;
    align-items: center;
    border-bottom: 0.1rem solid gainsboro;
  }

  .card_body {
    background-color: white;
    display: flex;
    direction: row;
    justify-content: space-evenly;
    align-items: flex-end;
    height: 10%;
    border-bottom: 0.1rem solid gainsboro;
    font-size: 1rem;
    font-weight: bold;
  }

  #card_footer {
    background-color: white;
    height: 40%;
  }

  h2 {
    color: white;
    font-size: 2rem;
    font-weight: bold;
  }

  h3 {
    font-size: 1.25rem;
    font-weight: bold;
    letter-spacing: -1px;
    line-height: 75%;
  }

  label {
    color: #5E39B3;
    font-size: 1.125rem;
    font-weight: bold;
    letter-spacing: -0.5px;
    margin-left: 0.5rem;
  }

  #update {
    z-index: 10;
    background-color: gray;
    color: white;
    font-size: 0.8rem;
    font-weight: bold;
    border-radius: 20px;
    border: none;
    padding: 0.2rem 0.9rem;
    margin-top: auto;
    margin-bottom: auto;
  }

  button {
    background-color: #5E39B3;
    color: white;
    font-size: 1rem;
    font-weight: bold;
    border: 1px #5E39B3 solid;
    border-radius: 30px;
    padding: 0.5rem 1rem;
    margin-bottom: 1rem;
    cursor: pointer;
    line-height: 1rem;
  }

  #footer_buttons {
    display: flex;
    justify-content: space-evenly;
    padding-left: 0.5rem;
    padding-right: 0.5rem;
  }

  #where {
    display: flex;
    flex-direction: column;
    margin: 1rem 0 1.2rem 0;
  }

  #at {
    display: flex;
    direction: row;
    justify-content: center;
    margin-top: 0.7rem;
    margin-bottom: 0.7rem;
  }

  #planet_img {
    width: 4rem;
    height: 4rem;
    min-width: 20px;
  }

  #profile_image {
    position: relative;
    align-self: center;
    z-index: 10;
    width: 150px;
    height: 150px;
    border-radius: 50%;
  } 
  #opacity {
    width: 100%;
    height: 100%;
    background-color: rgb(0, 0, 0, 0.2);
    position: absolute;
    left: 0;
  }
  #feed_write {
    margin-top: auto; 
    margin-bottom: auto;
  }
  #go_emotiontest {
    margin-top: auto; 
    margin-bottom: auto;
  }
</style>