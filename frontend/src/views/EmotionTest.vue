<template>
  <div id="test_container">
    <section id="test_header">
      <h1>감정테스트를 시작할게요</h1>
      <h3>지금 느끼는 감정을 모두 체크해보세요.</h3>
      <h3>오늘의 감정에 맞는 행성으로 데려다드려요!</h3>
    </section>
    <section id="selected_keywords_container">
      <label for="selected_keywords">지금까지 고른 키워드</label>
      <article id="selected_keywords">
        <p class="test_helper" v-if="!selected.length && testNum == 1">
          키워드는 최소 두 개, 최대 여섯 개까지 선택 가능해요
        </p>
        <p class="test_helper" id="test_2_helper" v-if="!selected.length && testNum == 2">
          이번에는 한 개 이상, 네 개 이하의 키워드를 선택해주세요
        </p>
        <selected-keyword v-for="(keyword, idx) in selected" :key="idx"
        :keyword="keyword" @delete_keyword="deleteKeyword" />
        <!-- <span id="refresh" @click="refresh_keywords" /> -->
      </article>
    </section>
    <section id="test_keywords_container">
      <transition-group id="test_transition" :name="page - before_page > 0 ? 'slide':'slide-reverse'">
        <article class="test_keywords" v-for="idx in page_of_keywords" v-show="page == idx" :key="'page-'+idx">
          <test-keyword v-for="keyword in keywords.slice(12 * (idx-1), 12 * idx)" :key="keyword.no" 
          :keyword="keyword" @checked="check" :ref="keyword.no"/>
        </article>
      </transition-group>
      <article id="paginator_container">
        <button v-for="idx in page_of_keywords" :key="'btn-'+idx"
         @click="before_page = page; page = idx" class="paginator" 
        :class="{ 'active_paginator' : page == idx }"></button>
      </article>
    </section>
    <section id="buttons">
      <button @click="nextTest" id="submit_test_btn">다 골랐어요</button>
      <button @click="go_to_back" id="return_to_btn">아직 안할래요</button>
    </section>
  </div>
</template>

<script>
  import TestKeyword from '@/components/EmotionTest/EmotionKeyword'
  import SelectedKeyword from '@/components/EmotionTest/SelectedKeyword'
  import axios from 'axios'
  // import index from '@/store/index.js'
  const session = window.sessionStorage;
  // const jwt = require('jsonwebtoken');

  export default {
    data: function(){
      return {
        page: 1,
        before_page: null,
        keywords: [],
        selected: [],
        testNum: 1
      }
    },
    components: {
      TestKeyword,
      SelectedKeyword
    },
    methods: {
      goToMain(){
        this.$router.push({ name:'Main' })
      },
      async userUpdate(res){
        const user = await this.$store.dispatch('accessTokenRefresh', res)
        console.log(user)
        this.goToMain()
      },
      check: function(keyword){
        const idx = this.selected.indexOf(keyword)
        const nums = this.selected.length

        console.log(keyword.name)
        console.log(this.selected)

        if (idx != -1){
          this.selected.splice(idx, 1)
        }
        else {
          if ((this.testNum == 1 && nums > 5) ||
          (this.testNum == 2 && nums > 3)){
            // alert('너무 많이 골랐어요..!')
            this.$store.commit('emotionTestTooMuchPickModalActivate')
            this.$refs[keyword.no][0].isChecked = false
          }
          else {
            this.selected.push(keyword)
          }
        }
      },
      deleteKeyword: function(keyword){
        const idx = this.selected.indexOf(keyword)

        if (idx != -1){
          this.selected.splice(idx, 1)
        }
        if (this.$refs[keyword.no].length > 0){
          this.$refs[keyword.no][0].isChecked = false
        }
      },
      nextTest: async function(){
        let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        if (this.testNum == 1){
          if (this.selected.length >= 2){
            axios({
              method: 'post',
              url: '/api/detailtest',
              data: this.selected,
              headers: headers,
            }).then((res) => {
            // console.log(res)
            this.keywords = res.data
            this.keywords = this.keywords.sort(() => Math.random() - 0.5)
            this.selected = []
            // alert('한 번만 더 선택해볼까요?')
            this.$store.commit('firstEmotionTestConfirmModalActivate')
            this.testNum = 2
            this.page = 1
            // console.log(this.page_of_keywords)
            this.$store.dispatch('accessTokenRefresh', res)
            })
            .catch(() => 
              this.$store.commit('emotionTestErrorModalActivate')
              // alert('잘못된 요청입니다')
            )
          }
          else {
            this.$store.commit('emotionTestPickMoreModalActivate')
            // alert('조금만 더 골라주세요🤣')
          }
        }
        else {
          if (this.selected.length > 0) {
            axios({
                method: 'post',
                url: '/api/resulttest',
                data: this.selected,
                headers: headers,
              }).then(res => {
              this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
              
              // alert(`당신은 ${ res.data.name }행성 입니다!`)
              // console.log("여기는 결과 네임")
              // console.log(`${res.data.name}`)
              // console.log(res.data.no)
              
              const userdata = JSON.parse(session.getItem('userInfo')) 
              // console.log('userdate===')
              // console.log(userdata) // 무드번호만 나옴......
              // console.log(userdata.no)
  
  
              // console.log("여기는 에러 직전")
              const body = { no: userdata.no, mood: res.data.no }
              console.log('2번째 감정 테스트 post')
              axios({
                method: 'put',
                url: '/api/users/update',
                data: body,
                headers: headers,
              }).then(res => {
                // console.log("여기는 데이터 수정하는 부분")
                // console.log(res)
                console.log('감정 수정')
                this.$store.dispatch('allTokenRefreshOnUserInfo', res)
                this.$store.commit('emotionTestResultModalActivate')
               
              }).catch(err => {
                console.log('2번째 감정 수정 오류', err)
                // console.log('user/update')
                // console.log(err)
              })
            })
            .catch((err) => {
              //같은 페이지에서 if문으로 나눠져 있으니까 같은 컴포넌트로 연결해도 되겠지??
              // console.log(err)
              console.log('2번째 감정 post 오류', err)
              this.$store.commit('emotionTestErrorModalActivate')
              // alert('잘못된 요청입니다.')
            })
          } else {
            this.$store.commit('emotionTestPickMoreModalActivate')
            // alert('단어를 골라주세요')
          }
        }
      },
      go_to_back: function(){
        this.$router.push({ name: 'Main' })
      },
    },
    computed: {
      page_of_keywords: function(){
        return Math.ceil(this.keywords.length / 12)
      }
    },
    created: function(){
      console.log(this.$store.state.userInfo)
      this.$store.state.recommendReload = 0
      let headers = {
      'at-jwt-access-token': session.getItem('at-jwt-access-token'),
      'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
			axios.get('/api/test', {
          headers: headers,
        })
        .then((res) => {
          this.keywords = res.data
          this.keywords = this.keywords.sort(() => Math.random() - 0.5)
          console.log(res);
          this.$store.dispatch('accessTokenRefresh', res)
        })
        .catch((error) => {
          console.log(error);
          this.$store.commit('ReturnToLoginModalActivate')
        })
        .finally(() => {
          console.log('getQSSList End!!');
          this.$store.commit('load', false)
        });
      },
  }
</script>

<style scoped>
  h1 {
    color: #5E39B3;
    font-size: 2.3rem;
    font-weight: bold;
    margin-bottom: 2rem;
  }

  h3 {
    font-size: 1.5rem;
    font-weight: bold;
    letter-spacing: -1px;
    margin: 0;
  }

  label {
    color: #5E39B3;
    font-size: 1.125rem;
    font-weight: bold;
    letter-spacing: -0.5px;
    margin-left: 0.5rem;
  }

  button {
    background-color: #5E39B3;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: 3px #5E39B3 solid;
    border-radius: 30px;
    padding: 0.4rem 1.125rem;
    margin-bottom: 1.125rem;
    cursor: pointer;
    line-height: 2rem;
  }

  #test_container {
    background-color: white;
    width: 30%;
    min-width: 800px;
    margin: 2rem auto;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: center;
    border-radius: 20px;
    border: 2px #5E39B3 solid ;
    padding: 3rem 4rem 1.5rem;
    }

  #test_header {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    align-self: flex-start;
    margin-bottom: 2rem;
  }

  #selected_keywords_container {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    align-self: stretch;
    margin-bottom: 1rem;
  }

  #selected_keywords {
    width: 100%;
    min-height: 6vh;
    padding: 0.5rem;
    border-bottom: 1px #5E39B3 solid;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    position: relative;
  }

  .test_helper {
    margin: 0;
    color: #777777;
  }

  @keyframes gliter {
    from { opacity: 100%; }
    to { opacity: 50%;; }
  }

  #test_2_helper {
    color: rgb(85, 85, 255);
    animation: gliter 0.75s ease-in-out 0s infinite alternate;
  }

  #refresh {
    background-image: url('../assets/images/icons/refresh.png');
    background-size: cover;
    width: 1.5rem;
    height: 1.5rem;
    position: absolute;
    right: 0;
    cursor: pointer;
  }

  #test_keywords_container {
    width: 100%;
    height: 30vh;
    min-height: 300px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border-bottom: 1px #5E39B3 solid;
    margin-bottom: 2rem;
  }

  #test_transition {
    width: 100%;
    height: 75%;
    display: flex;
    justify-content: center;
    flex-wrap: wrap;
    position: relative;
    overflow: hidden;
  }

  .test_keywords {
    display: flex;
    justify-content: center;
    flex-wrap: wrap;
    position: absolute;
    padding: 0.5rem 1rem;
    width: 100%;
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
    animation: slide-in 1s ease-in-out;
  }

  .slide-leave-active {
    animation: slide-out 1s ease-in-out;
  }

  .slide-reverse-enter-active {
    animation: slide-out 1s ease-in-out reverse;
  }

  .slide-reverse-leave-active {
    animation: slide-in 1s ease-in-out reverse;
  }

  #paginator_container {
    margin: 1rem auto;
  }

  @keyframes glitter {
    from { opacity: 0%; }
    to { opacity: 100%; }
  }

  .paginator{
    background-color: white;
    border: 2px rgb(128, 128, 128, 0.75) solid;
    width: 1rem;
    height: 1rem;
    padding: 0;
    margin: 1rem 1rem 0;
  }

  #buttons {
    width: 50%;
    display: flex;
    justify-content: space-between;
  }

  #return_to_btn {
    background-color: #777777;
    border: 3px #777777 solid;
  }

  .active_paginator {
    background-color: #777777;
  }
</style>