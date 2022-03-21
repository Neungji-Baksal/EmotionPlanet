<template>
  <section id="text-container">
    <article id="subs">
      <img src="../../assets/images/icons/return.png" alt="" id="back" @click="out">
      <h1>글 쓰기</h1>
    </article>
    <article id="text-header">
      <h3>이제 자유태그와 글을 작성할 수 있습니다!</h3>
      <h3>여러분의 하루를 공유해주세요</h3> 
    </article>
    <div v-if="feedData.tags.length" id="pickTags">
      <div id="moodTag">
        <img id="planet_img" :src="require('@/assets/images/emotions/' + planetImg)" alt="">
        <p style="margin:auto 0.2rem; color: #5E39B3; font-weight: bold;">{{feedData.tags[0].name}}행성</p>
      </div>
      <div id="actTag">
        <p style="margin:auto 0.2rem; color: #5E39B3; font-weight: bold;">{{feedData.tags[1].name}}</p>
      </div>
      <div id="freeTag" v-if="feedData.tags.slice(2).length === 0">
        <p id="freeTag" style="margin:auto 0.2rem; color: blue; font-weight: bold;"># 자유태그를 #입력해주세요</p>
      </div>
      <div id="freeTag" v-else style="flex-wrap: wrap;">
        <div id="freeTag" v-for="(tag, idx) in feedData.tags.slice(2)" :key="idx" style="flex-wrap: wrap;"> 
            <p v-if="tag.name" id="pickTag" style="margin:auto 0.2rem; color: blue; font-weight: bold; word-brake: brake-all;">
              # {{tag.name}}
            </p> 
            <p v-else></p>        
        </div>
      </div>
    </div>
    <div id="freeTag_write">
      <input type="text" id="tag_input" @keyup.enter="keyPress" @blur="keyPress" placeholder="자유태그를 작성 후 엔터키를 눌러 주세요">
      <img id="write" @click="freeTagCreate" src="@/assets/images/icons/write.png" alt="" style="width:1.6rem;height:1.6rem; cursor: pointer;">
    </div>
    <textarea id="text-input" placeholder="" v-model="feedData.descr" />
    <footer>
      <button id="btn-before" @click="beforePage">이전</button>
      <button id="btn-next" @click="feedWrite">작성</button>
    </footer>
  </section>
</template>

<script>
import {mapState} from 'vuex'
import axios from 'axios'

const session = window.sessionStorage;

export default {
  name: 'CreateText',
  data: function () {
    return {
      isChecked: false,
      freeTag: null,
      // feedText: null,
      feedData: {
        descr: '',
        author: null,
        tags: [],
      },
      Feedimages: [],
      planetImg: null,
    }
  },
  methods: {
    out(){
      this.$emit('out')
    },
    beforePage(){
      this.$emit('before-page')
    },
    keyPress (event) {
      console.log(event.target.value)
      this.freeTag = event.target.value 
      this.feedData.tags.push({name: `${this.freeTag}`, type: 0})
      console.log(this.feedData)
      event.target.value = null
    },
    freeTagCreate () {
      let free_tag_value = document.getElementById('tag_input').value
      this.freeTag = free_tag_value
      this.feedData.tags.push({name: `${this.freeTag}`, type: 0})
      console.log(this.feedData.tags)
      document.getElementById('tag_input').value = null
    },
    feedWrite () {
      console.log(this.feedData)
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      const formData = new FormData();
      this.Feedimages.forEach((file) => formData.append("files", file.image));
      this.Feedimages.forEach((file) => console.log(file));
      
      formData.append(
        "userInfo",
        new Blob([JSON.stringify(this.feedData)], { type: "application/json" })
      );

      axios({
          method: 'post',
          url: '/api/feeds',
          data: this.feedData, // post 나 put에 데이터 넣어 줄때
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
            console.log("피드 작성 : " + res.data)
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서


          axios({
            method: 'post',
            url: '/api/s3/file/' + res.data,
            data: formData, // post 나 put에 데이터 넣어 줄때
            headers: headers,  // 넣는거 까먹지 마세요
          }).then((res) => {
            console.log(res.data)
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            this.feedData.tags = []
            this.feedData.descr = ''
            this.Feedimages = []
            this.$store.commit('navActivate', 0)
            // console.log('이것은' , this.feedData.tags)
            this.$router.go(0)
          }).catch((error) => {
            console.log(error);
          });

        }).catch((error) => {
          console.log(error);
        }).then(() => {
          console.log('getQSSList End!!');
        });

    },
    feedUpdate () {
      let headers = {
        'Content-Type': 'multipart/form-data',
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };

      const formData2 = new FormData();
      this.Feedimages.forEach((file) => formData2.append("multipartFile", file.image));
      this.Feedimages.forEach((file) => console.log(file));
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
          console.log("피드 작성 : " + res.data)
          this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
      }).catch((error) => {
        console.log(error);
      }).then(() => {
        console.log('getQSSList End!!');
      });
    },
  },
  computed: 
    mapState([
      'feedCreateData', 'planetStyles', 'rawImg'
    ]),
  created: function () {
    this.Feedimages = this.rawImg
    this.feedData.author = this.feedCreateData[0].author
    this.feedData.tags = [...this.feedCreateData[0].tags]

    let mood = this.$store.state.userInfo.mood
    let planetstyle = this.planetStyles.find(el => el.id === mood) || {}
		this.planetImg = planetstyle.img
    console.log(this.feedData)
  }, 
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
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
  }
  
  button {
    background-color: #5E39B3;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: 3px #5E39B3 solid;
    border-radius: 30px;
    padding: 0.2rem 2rem;
    margin: 1rem;
    cursor: pointer;
    line-height: 2rem;
  }

  input:focus, textarea:focus {
    outline-color: #5E39B3;
  }
  input::placeholder {
    font-weight: initial;
    text-shadow: none;
    position: absolute;
  }

  label {
    color: #5E39B3;
    font-weight: bold;
    margin-left: 0.5rem;
    font-size: 1.125rem;
  }

  #text-container {
    display:flex;
    flex-direction: column;
    justify-content: flex-start;
    align-items: center;
    width: 100%;
    height: 100%;
    padding: 0;
  }

  #subs {
    display:flex;
    justify-content: center;
    border-bottom: 1px #cccccc solid;
    width: 100%;
    padding: 0.5rem;
    position: relative;
  }

  #back {
    width: 25px;
    height: 25px;
    position: absolute;
    left: 2%;
    cursor: pointer;
  }

  #text-header {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    width: 80%;
    margin: 1.5rem 1rem 1rem;
  }

  #tag_input {
    width: 93%;
    border-style:none;
    outline: none;
    padding-left:0.3rem;
    margin-top: 0.3rem;
  }

  #text-input{
    width: 80%;
    height: 50%;
    border: 2px #cccccc solid;
    border-radius: 10px;
    padding: 1rem;
    resize: none;
  }

  footer {
    display:flex;
    justify-content: right;
    width: 80%;
    margin: 1rem;
  }

  #secret {
    display:flex;
    flex-direction: row;
    justify-content: left;
    align-items: center;
  }

  #btn-before {
    background-color: #777777;
    border: 3px #777777 solid;
  }
  #pickTags {
    display: flex;
    flex-direction: row;
    flex-wrap: wrap;
    justify-content: left;
    width: 80%

  }
#planet_img {
	width: 2rem;
	height: 2rem;
  margin: 0.2rem;
}
#moodTag {
  display: flex;
  flex-direction: row;
  border: 1.5px #5E39B3 solid;
  border-radius: 20px;
  margin-right: 0.3rem;
}
#actTag {
  display: flex;
  flex-direction: row;
  border: 1.5px #5E39B3 solid;
  border-radius: 20px;
  margin-right: 0.3rem;
}
#freeTag {
  display: flex;
  flex-direction: row;
  margin-right: 0.3rem;
}
#freeTag_write{
  display: flex;
  flex-direction: row;
  width:80%;
  border:0.2rem solid gainsboro;
  border-radius: 10px;
  margin-top: 1rem;
  margin-bottom:1rem;
  height: 6%
}
</style>