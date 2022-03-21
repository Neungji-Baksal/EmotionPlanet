<template>
  <div id="music-container">
    <h3>{{ tmp.name }}에 흐르는 별소리</h3>
    <div id="img-box">
      <transition-group id="carousel" name="slide">
        <span class="postCard" v-for="(music, idx) in musicData" :key="idx" v-show="idx >= page && idx < page + 4">
          <img class="postImg" :src="music.imgLink" :alt="music.title">
          <p class="postTitle">{{ music.title }}</p>
          <img @click="addPlayList(music)" id="goldstar" src="@/assets/images/icons/goldstar.png" alt="like"> 
        </span>
      </transition-group>
      <span id="left" v-if="page > 0" class="carousel-btn" @click="pagination(false)"/>
      <span id="right" v-if="page + 4 < musicData.length" class="carousel-btn" @click="pagination(true)"/>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
    name:'MusicList',
    data() {
      return {
        music: null,
        type:0,
        sendData:null,
        page: 0,
      }
    },
    props: {
      tab: Number
    },
    computed: {
      tmp: function () {
        const mood = this.$store.state.userInfo.mood
        const style = this.$store.state.planetStyles.find(el => el.id === mood) || {}
        return style
      },
      musicData(){
        if (this.music){
          return this.music.slice(10 * this.tab, 10 * (this.tab+1))
        }
        return 0
      },
    },
    methods: {
      pagination(payload){
        if (this.page + 4 < this.musicData.length && payload){
          this.page ++
        }
        else if (this.page > 0 && !payload){
          this.page --
        }
      },
      addPlayList:function(item){
        this.sendData=[this.type, item]
        this.$store.commit('addPlayListActive',this.sendData)
      }
    },
    created(){
      const session = window.sessionStorage
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };

      axios.get('/api/recommend/music/' + this.$store.state.userInfo.mood, {
        headers: headers,
      }).then((res) => {
        this.music = res.data
        this.$store.dispatch('accessTokenRefresh', res)
        this.$emit('comp')
      })
      .catch((err) => {
        console.log('err music', err);
      })
      .finally(() => {
        console.log('get music data End!!');
      });
    },
  }
</script>

<style scoped>
  h3 {
    text-align: left;
    margin-left:3rem;
    font-weight: bold;
    font-size: 2rem;
  }

  p {
    font-size: 1.125rem;
    font-weight: bold;
    margin: 0.5rem;
  }

  #music-container {
    margin: 2rem 0;
  }

  #goldstar {
    position: absolute;
    cursor: pointer;
		width: 2rem;
		height: 2rem;
    right: 1%;
    top:55%;
  }

  #img-box {
    width: 90%;
    position: relative;
    margin: auto;
  }

  #carousel {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr 1fr;
    align-items: center;
    width: 100%;
    position: relative;
    overflow: hidden;
    border-radius: 20px;
    gap: 1rem;
    padding: 1rem;
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

  .postCard {
    width: 100%;
    aspect-ratio: 1/1.45;
    border: 1px #cccccc solid;
    border-radius: 20px;
    overflow: hidden;
    box-shadow: 2px 4px 8px #777777;
    position: relative;
    transition: opacity 1s;
  }

  .postImg {
    width: 100%;
    aspect-ratio: 1/1;
  }

  .slide-leave-active {
    position: absolute;
    width: 0;
  }

  .slide-enter, .slide-leave-to {
    opacity: 0;
  }
  
  #left {
    background-image: url('../../../assets/images/icons/left.png');
    left: -2%;
  }

  #right {
    background-image: url('../../../assets/images/icons/right.png');
    right: -2%;
  }
</style>