<template>
  <div id="movie-container">
    <h3>{{ tmp.name }}에 보이는 은하수</h3>
    <div id="img-box">
      <transition-group id="carousel" name="slide">
        <span class="postCard" v-for="(movie, idx) in movieData" :key="idx" v-show="idx >= page && idx < page + 4">
          <img class="postImg" :src="movie.imgLink" :alt="movie.title">
          <p class="postTitle">{{ movie.title }}</p>
          <img @click="addPlayList(movie)" id="goldstar" src="@/assets/images/icons/goldstar.png" alt="like"> 
        </span>
      </transition-group>
      <span id="left" v-if="page > 0" class="carousel-btn" @click="pagination(false)"/>
      <span id="right" v-if="page + 4 < movieData.length" class="carousel-btn" @click="pagination(true)"/>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
    name:'MovieList',
    data() {
      return {
        movie: null,
        type:1,
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
       movieData(){
        if (this.movie){
          return this.movie.slice(10 * this.tab, 10 * (this.tab+1))
        }
        return 0
      },
    },
    methods: {
      pagination(payload){
        if (this.page + 4 < this.movieData.length && payload){
          this.page ++
        }
        else if (this.page > 0 && !payload){
          this.page --
        }
      },
      addPlayList:function(item){
        this.sendData=[this.type,item]
        this.$store.commit('addPlayListActive',this.sendData)
        // console.log(this.$store.state.recommendMusic)
      }
    },
    created(){
      const session = window.sessionStorage
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      axios.get('/api/recommend/movie/' + this.$store.state.userInfo.mood, {
        headers: headers,
      })
      .then((res) => {
        this.movie = res.data
        this.$store.dispatch('accessTokenRefresh', res)
        this.$emit('comp')
      })
      .catch(() => {
        console.log('err movie');
      })
      .then(() => {
        console.log('get moive data End!!');
      });
    }
  }
</script>

<style scoped>
   h3 {
    text-align: left;
    margin-left: 3rem;
    font-weight: bold;
    font-size: 2rem;
  }

  p {
    font-size: 1.125rem;
    font-weight: bold;
    margin: 0.5rem;
  }
  
  #movie-container {
    margin: 2rem 0;
  }

  #goldstar {
    position: absolute;
    cursor: pointer;
		width: 2rem;
		height: 2rem;
    right: 1%;
    top: 65%;
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
    aspect-ratio: 1/1.75;
    border: 1px #cccccc solid;
    border-radius: 20px;
    overflow: hidden;
    box-shadow: 2px 4px 8px #777777;
    position: relative;
    transition: opacity 1s;
  }

  .postImg {
    width: 100%;
    aspect-ratio: 1/1.35;
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