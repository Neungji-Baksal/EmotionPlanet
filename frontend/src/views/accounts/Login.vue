<template>
  <div id="login_container">
    <div id="login_innercontainer">
      <div id="login_header">
        <h1 style="font-size: 2.5rem;">어서오세요!</h1>
        <h1 style="font-size: 2.5rem;">오늘은 어떤 이야기를</h1>
        <h1 style="font-size: 2.5rem;">들려주실건가요? 😉</h1>
      </div>
      <br>
      <form @submit.prevent="login" id="login_body">
        <article id="email_form">
          <label for="email">이메일</label>
          <input type="text"
          id="email"
          v-model="credentials.email"
          placeholder="이메일을 입력해주세요"
          autocomplete="off">
        </article>
        <article id="password_form">
          <label for="pw">비밀번호</label>
          <input type="password" 
          id="pw"
          v-model="credentials.pw"
          placeholder="비밀번호를 입력해주세요">
        </article>
        <div id="link">
          <router-link :to="{ name: 'EmailFind' }" style="font-size: 1rem;">이메일 찾기</router-link>
          <router-link :to="{ name: 'Password-find' }" style="font-size: 1rem;">비밀번호 찾기</router-link>
          <router-link :to="{ name: 'Signup' }" class="gosignup" style="font-size: 1rem;">회원가입</router-link>
        </div>
        <br>
        <button id="login_btn">로그인</button>
      </form>
      <button id="google" class="social_login" @click="handleClickSignIn">
        <img id="google_img" src="../../assets/images/etc/Google__G__Logo.png">
        <p>Google로 로그인</p>
      </button>
      <article>
        <button id="kakao" class="social_login" @click="handleClickKaKaoSignin">
          <img id="kakao_img" src="../../assets/images/etc/kakao.png">
          <p>Kakao로 로그인</p>
          </button>
      </article>
      <!-- <button id="kakao" class="social_logout" @click="logout">로그아웃</button> -->
    </div>
  </div>
</template>

<script>
import axios from 'axios'

const session = window.sessionStorage;
const jwt = require('jsonwebtoken');

export default {
  name: 'Login',
  data: function () {
    return {
      credentials: {
        email: null, 
        pw: null,
      },
      googleUser: null,
      kakaoOauthUrl: null,
    }
  },
  methods: {
    //OAUTH
  async handleClickSignIn() {
    try {
      const googleUser = await this.$gAuth.signIn();
      if (!googleUser) {
        return null;
      }
      console.log("googleUser", googleUser);
      console.log("getId", googleUser.getId());
      console.log("getBasicProfile", googleUser.getBasicProfile());
      console.log("getAuthResponse", googleUser.getAuthResponse());
      console.log(
        "getAuthResponse",
        this.$gAuth.GoogleAuth.currentUser.get().getAuthResponse()
      );
      this.isSignIn = this.$gAuth.isAuthorized;
      this.onSuccess(googleUser)
    } catch (error) {
      //on fail do something
      this.onFailure(error)
    }
  },
  onSuccess(googleUser) {
    // eslint-disable-next-line
    console.log(googleUser);
    this.googleUser = googleUser;
    this.tokenVerify()
  },
  onFailure(error) {
    // eslint-disable-next-line
    console.log(error);
  },
  login: function() {
    axios({
      method: 'post',
      url:'/api/login',
      data: this.credentials
    })
    .then((res)=>{
      console.log('response!!', res.headers);
      // storage 설정
      session.setItem('at-jwt-access-token', res.headers['at-jwt-access-token']);
      session.setItem('at-jwt-refresh-token', res.headers['at-jwt-refresh-token']);

      this.$store.dispatch('allTokenRefresh', res)
      
      this.sendToken();
      // this.$router.push('EmotionTest')
      // this.$router.push({ name: 'Main' })
      console.log(res)
      this.$store.commit('loginConfirmModalActivate')
    })
    .catch(err=> {
      console.log(err)
      console.log('나는 에러야!', err.response.data.message)
      this.$store.commit('loginFailModalActivate', err.response.data.message)
      // alert(err.response.data.message) // 서버측에서 넘어온 오류 메시지 출력.
    })
    this.credentials.email = "";
    this.credentials.pw ="";
  },

  tokenVerify() {
    const url = '/api/login/auth';
    const params = new URLSearchParams();
    params.append('idToken', this.googleUser.wc.id_token);
    console.log(params)
    axios.post(url, params).then((res) => {
      // alert("로그인 성공")
      console.log(res.headers);
      this.$store.dispatch('allTokenRefresh', res)
      console.log(this.$store.state.userInfo.email)
      this.sendToken();
      if (this.$store.state.userInfo.tel === null) {
        this.$router.push('/moreInfo')
      }
      else{
        this.$store.commit('loginConfirmModalActivate')
        // this.$router.push('EmotionTest')
      }
    }).catch((error) => {
      console.log(error);
      // this.$store.commit('loginFailModalActivate')
    })
  },

  sendToken() {
    console.log('나는 sendToken!')
    const decodeAccessToken = jwt.decode(session.getItem('at-jwt-access-token'));
    let headers = null;
    if(decodeAccessToken.exp < Date.now()/1000 + 60){
      console.log('만료됨!!');
      headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      }
      console.log('headers : ', headers);
    }else{
      console.log('만료되지않음!!');
      headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      }
      console.log('headers : ', headers);
    }
  },

  handleClickKaKaoSignin() {
    const params = {
        redirectUri: "https://i6e203.p.ssafy.io/login/KaKaoLogin",
    };
    window.Kakao.Auth.authorize(params);
  },

  kakaoValidate(code) {
    console.log("카카오로그인 시작")
    axios({
        method: 'post',
        url: '/api/login/oauth_kakao',
        data: code
      }).then((res) => {
        console.log('카카오 데이터 받아오기 : ' + res.data)
        this.kakaoOauthUrl = res.data
      }).catch((error) => {
        console.log(error);
      }).then(() => {
        console.log('getQSSList End!!');
      });
  },

  logout() {
		window.Kakao.Auth.logout(function(response) {
			alert(response + 'logout');
		}); 
  },
  
  trans() {
    let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
    };
    let data = {
      name: '',
      type: ''
    };
    axios({
        method: 'get',
        url: '/api/qss/list',
        data: data, // post 나 put에 데이터 넣어 줄때
        headers: headers,  // 넣는거 까먹지 마세요
      }).then((res) => {

      this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
      this.dispatch('accessTokenRefresh', res) // store에서

      }).catch((error) => {
        console.log(error);
      }).then(() => {
        console.log('getQSSList End!!');
      });
    },
  },
  created(){
    this.$store.commit('load', false)
  }
}
</script>

<style scoped>
  @import '../../assets/styles/globalstyle.css';
  
  label {
    color: #5E39B3;
    font-weight: bold;
    margin-left: 0.5rem;
    font-size: 1.125rem;
  }
  input {
    border: 2px #5E39B3 solid;
    border-radius: 30px;
    width: 100%;
    min-width: 300px;
    height: 5vh;
    min-height: 40px;
    padding: 0.75rem;
    font-size: 1.5rem;
    font-weight: bold;
  }

  input:focus {
    outline: none;
    background-color: #afa0d6;
    color: white;
    text-shadow: 0 1px 2px rgb(0, 0, 0, 0.5);
  }

  input[type="password"] {
    font-size: 3rem;
  }

  input::placeholder {
    font-size: 1.25rem !important;
    font-weight: initial;
    text-shadow: none;
    position: absolute;
    top: 20%;
  }

  input:focus::placeholder {
    color: transparent;
  }

  a {
    color: black;
    text-decoration: none;
    font-size: 0.9rem;
    font-weight: bold;
    letter-spacing: -1px;
  }

  button {
    background-color: #5E39B3;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: none;
    border-radius: 20px;
    padding: 0.4rem 1.125rem;
    margin-bottom: 1.125rem;
    cursor: pointer;
  }
  #google_img {
    width: 4vh;
    height: 4vh;
    margin-left: 0.4rem;
    margin-right: 1rem;
  }
  #kakao_img {
    width: 5vh;
    height: 5vh;
    margin-right: 1rem;
  }

  p {
    margin: 0;
  }

  #login_container{
    background-color: white;
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
    align-items: center;
    background-color: white;
    width: 25%;
    align-self: center;
    min-width: 600px;
    min-height: 92.5vh;
    /* height: 100%; */
    padding: 2rem;;
    border-radius: 20px;
    border: 2px  #5E39B3 solid;
    /* border-left: 2px #5E39B3 solid;
    border-right: 2px #cccccc solid; */
  }
  #login_innercontainer{
    width: 85%;
    margin-left: auto;
    margin-right: auto;
    margin-top: 1rem;
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  #login_header{
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    align-self: flex-start;
  }

  #login_header h1 {
    margin: 0;
    font-size: 2rem;
    font-weight: bold;
    letter-spacing: -1px;
  }

  #login_body{
    width:90%;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 1rem;
  }

  #login_body article {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    width: 100%;
  }

  #login_body > *:first-child {
    margin-bottom: 1.25rem;
  }

  #link{
    width: 75%;
    display: flex;
    justify-content: space-evenly;
    margin: 1.25rem;
  }

  #login_btn{
    font-size: 1.25rem;
    padding: 0.5rem 2rem;
    width: 15vh;
    min-width: 150px;
  }

  .social_login {
    display: flex;
    justify-content: center;
    align-items: center;
    background-color: #F0EDE7;
    color: black;
    width: 35vh;
    min-width: 300px;
    height: 4.5vh;
    min-height: 45px;
    margin: 0.75rem;
  }

  /* #kakao{
    width: 3.5vh;
  } */
</style>