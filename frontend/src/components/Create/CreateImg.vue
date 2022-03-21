<template>
  <section id="img-container">
    <article id="subs">
      <img src="../../assets/images/icons/return.png" alt="" id="back" @click="out">
      <h1 id="title">글 쓰기</h1>
    </article>
    <article id="img-box">
      <div id="default-box" v-if="!images.length">
        <img src="../../assets/images/icons/image.png" alt="" id="default-img">
        <p id="img-text">이미지를 올려주세요</p>
      </div>
      <div id="uploaded-box" v-else>
        <transition-group id="carousel" :name="page > beforePage ? 'slide':'slide-reverse'">
          <img v-for="(image, index) in images" :key="index"
          class="uploadedImg" :src="image.imgLink" alt=""
          v-show="index+1 == page">
        </transition-group>
        <div id="pages">
          <span v-for="idx in images.length" :key="idx" 
          :class="['page-num', {'here':idx==page}]" @click="paginationByDot(idx)" />
        </div>
        <span id="left" class="carousel-btn" @click="pagination(false)"/>
        <span id="right" class="carousel-btn" @click="pagination(true)"/>
      </div>
    </article>
    <br>
    <footer>
      <div class="imgUpload">
        <label for="file">이미지 업로드</label> 
        <input type="file" id="file" accept="image/*" @change="imgUpload" ref="feedImg" multiple>
      </div>
      <button id="btn-next" @click="nextPage">다음</button>
    </footer>
  </section>
</template>

<script>
import {mapState} from 'vuex'

export default {
  data () {
    return {
      page: 1,
      beforePage: 1,
      images: [],
      uploadImageIndex: 0,
      feedDto: {
        descr: null,
        author: null,
        tags: [],
      },
      rawImage: [],
    }
  },
  methods: {
    out(){
      this.$emit('out')
    },
    nextPage(){
      if (this.images.length === 0) {
        // alert('이미지를 선택해주세요')
        this.$store.commit('pickYourImageModalActivate')
      } else {
        this.$emit('next-page')
      }
    },
    imgUpload () {
      // this.$store.commit('feedImg', img)
      this.images = []
      this.rawImage = this.$refs.feedImg.files;
      
      let num = -1;
      for (let i =0; i < this.$refs.feedImg.files.length; i++) {
        this.images = [
          ...this.images,
          {
            image: this.$refs.feedImg.files[i],
            imgLink: URL.createObjectURL(this.$refs.feedImg.files[i]),
            number: i
          }
        ];
        num = i;
      }
      this.uploadImageIndex = num + 1;

      if (this.images.length > 3) {
        // alert('사진이 너무 많습니다')
        this.images = []
        this.$store.commit('tooMuchImagesModalActivate')
      } else {
        this.$store.commit('feedImg', this.images)
        this.$store.commit('rawImg', this.rawImage)
        // console.log('성공')
      }
    },
    pagination(payload){
      this.beforePage = this.page
      if (this.page < this.images.length && payload){
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
  computed: 
    mapState([
      'userInfo', 'planetStyles',
    ]
  ),
  created: function () {
    this.feedDto.author = this.userInfo.no
    console.log(this.feedDto)

    for (let planet of this.planetStyles) {
      if (planet.id === this.userInfo.mood) {
        let PlanetName = planet.name.slice(0,-2)
        console.log(PlanetName)
        this.feedDto.tags.push({name: PlanetName, type: 1 })
      }
    }
    console.log(this.feedDto.tags)
    this.$store.commit('feedUserData', this.feedDto)
  }
}
</script>

<style scoped>
  h1 {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
  }

  h2 {
    font-size: 2rem;
    font-weight: bold;
    margin-bottom: 2rem;
  }

  h3 {
    font-size: 1.25rem;
    margin: 0;
  }
  
  button {
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

  #img-container {
    display:flex;
    flex-direction: column;
    justify-content: flex-start;
    align-items: center;
    width: 100%;
    height: 100%;
  }

  #subs {
    display:flex;
    justify-content: center;
    width: 100%;
    height: 8%;
    position: relative;
    border-bottom: 2px #cccccc solid;
    padding: 0.5rem;
  }

  #back {
    width: 25px;
    height: 25px;
    position: absolute;
    left: 2%;
    cursor: pointer;
  }

  #img-box {
    display: flex;
    flex-direction: column;
    width: 85%;
    height: 85%;
    background-color: lightgray;
    border-radius: 20px;
    margin: auto;
    justify-content: center;
    align-items: center;
    margin: 1rem 1rem 0rem 1rem;
  }
  #default-box{
    text-align: center;
    margin: auto;
  }
  #default-img {
    width: 3rem;
    height: 3rem;
  }

  #uploaded-box {
    width: 100%;
    height: 100%;
    position: relative;
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

  .uploadedImg {
    width: 100%;
    height: 100%;
    margin: auto;
    aspect-ratio: 1/1;
    position: absolute;
  }

  #img-text{
    color: gray;
  }

  footer {
    display:flex;
    justify-content: space-between;
    width: 90%;
    margin: 0.5rem;
  }

  .imgUpload label {
    background-color: #5E39B3;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: 3px #5E39B3 solid;
    border-radius: 20px;
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
    margin: 0rem 1rem 1rem 1rem;
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
</style>
