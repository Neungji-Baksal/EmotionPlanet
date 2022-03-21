<template>
  <div id="pu_container">
    <section id="pu_header">
      <h1>프로필 변경</h1>
    </section>
    <section id="pu_body">
			<article id="profile_head">
				<img id="profile_img" :src="this.$store.state.userInfo.profileImg" alt="">
        <p id="user_id">{{ this.$store.state.userInfo.nickname }}</p>
        <div id="profile_img_change">
          <button id="profile_img_change_button" @click="profileImgChangeModal">사진 변경</button>
        </div>
			</article>
			<br>
      <br>
      <article id="pu_form" style="display: flex; flex-direction: row; justify-content: space-between">
        <label style="margin-left:1rem;">이메일</label>
        <p id="user_email">{{ this.$store.state.userInfo.email }}</p>
      </article>
      <br>
			<article id="pu_form">
        <label for="username" style="margin-left:1rem;">닉네임</label>
        <input 
        id="nickname"
        v-model="credentials.beforeNick"
        @input= "checkNickname" autocomplete="off" maxlength="10">
        <span v-if="credentials.beforeNick !== $store.state.userInfo.nickname">
          <p v-if="!isValid.validateNicknamelength" class="warn" style="margin-left:1.5rem;">
            닉네임은 2자 이상, 10자 이하입니다.
          </p>
          <p v-if="!isValid.validateNicknamecheck && isValid.validateNicknamelength" class="warn" style="margin-left:1.5rem;">
            사용 중인 닉네임이에요.
          </p>
          <p v-if="isValid.validateNicknamecheck && isValid.validateNicknamelength" class="collect" style="margin-left:1.5rem;">
           사용 가능한 닉네임입니다.
          </p>
        </span>
			</article>
      <br>
      <article id="pu_form" style="display: flex; flex-direction: row; justify-content: space-between">
        <label for="user_birth" style="margin-left:1rem;">생년월일</label>
        <p id="user_birth">{{ this.$store.state.userInfo.birth }}</p>
      </article>
			<br>
			<article id="pu_form">
				<label id="introduce" style="margin-left:1rem;">소개</label>
        <textarea  
        id="short_comment"
        v-model="$store.state.userInfo.intro"
        ></textarea>
			</article>
			<br>
      <article id="pu_form">
        <div id="pwactive">
          <label for="next_pw" style="margin-bottom:0.5rem; margin-left:1rem;">변경할 비밀번호</label>
          <article id="pwchange">
            <input style="margin-top:auto;margin-bottom:0.9rem" 
            type="checkbox" @click="pw_change"
            >
            <h5 style="margin-top:auto;margin-bottom:0.5rem;margin-left:0.3rem;">비밀번호 변경하기</h5>
          </article>
        </div>
        <input type="password" 
        :id="pwActivate == true ? 'change' : 'still'"
        :disabled="pwActivate == false"
        v-model="credentials.nextPw"
        @input="pwCheck"
        placeholder="비밀번호는 8자 이상, 20자 이하입니다." style="margin-top:0.2rem;"
        >
        <span v-if="credentials.nextPw">
          <p v-if="!isValid.validateNextPw" class="warn">
            사용할 수 없는 비밀번호에요.
          </p>
          <p v-if="isValid.validateNextPw" class="collect">
            사용할 수 있는 비밀번호입니다.
          </p>
        </span>
      </article>
			<br>
      <article id="pu_form">
        <label for="pw_conf" style="margin-left:1rem;">비밀번호 확인</label>
        <input type="password"
        :id="pwActivate == true ? 'change' : 'still'"
        :disabled="pwActivate == false"
        v-model="credentials.pwConf"
        @input="pwConfCheck"
        placeholder="비밀번호를 다시 입력해주세요." style="margin-top:0.2rem;"
        >
        <span v-if="credentials.pwConf">
          <p v-if="!isValid.validatePwConf" class="warn">
            비밀번호가 맞지 않아요.
          </p>
          <p v-if="isValid.validatePwConf" class="collect">
            비밀번호가 일치합니다.
          </p>
        </span>
      </article>
      <br>
      <!-- <article id="pu_form_radio">
        <label for="" style="margin-left:1rem;">계정 공개 여부</label>
        <div id="check_radio">
          <div id="on">
            <input type="radio" id="show_all" style="width:20px;height:20px;border:1px;" name="group"
            @change="$store.state.userInfo.publish = 1"
            :checked="$store.state.userInfo.publish == 1 ? 'checked': false">
            <h5>모두에게 공개</h5>
          </div>
          <div id="off">
            <input type="radio" id="show_followers" style="width:20px;height:20px;border:1px;" name="group"
            @change="$store.state.userInfo.publish = 2"
            :checked="$store.state.userInfo.publish == 2 ? 'checked': false">
            <h5>팔로워에게 공개</h5>
          </div>
        </div>
        <br>
      </article> -->
      <article id="pu_buttons">
        <button id="withdrawal" @click="go_to_withdrawal">회원 탈퇴</button>
        <button id="pu_button" @click="user_change">변경하기</button>
      </article>
    </section>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  data: function(){
    return {
      credentials : {
        beforeNick: null,
        beforeIntro: null,
        beforePw: null,
        nextPw: null, //변경할 비밀번호
        pwConf: null, //비밀번호 확인
      },
      isValid: {
        validateNicknamelength : true, // 닉네임 길이 체크
        validateNicknamecheck : false, // 중복 닉네임 여부
        validateNextPw: false, //변경할 비번 체크
        validatePwConf: false, //비밀번호 확인 체크
      },
      help: false, 
      pwActivate: false,
    }
  },
  methods: {
    pwCheck: function(){
      if (this.credentials.nextPw && this.credentials.nextPw.length >= 8 && this.credentials.nextPw.length <= 20){
        this.isValid.validateNextPw = true
      }
      else {
        this.isValid.validateNextPw = false
      }
    },
    pwConfCheck: function(){
      if (this.credentials.pwConf && this.credentials.nextPw === this.credentials.pwConf){
        this.isValid.validatePwConf = true
      }
      else {
        this.isValid.validatePwConf = false
      }
    },
    go_to_withdrawal: function(){
      this.$router.push('/setting/withdrawal')
    },
    profileImgChangeModal:function(){
      this.$store.commit('profileImgChangeModalActivate')
		},
    checkNickname: function(el){
      this.credentials.beforeNick = el.target.value
      if (this.credentials.beforeNick !== this.$store.state.userInfo.nickname) {
        if (this.credentials.beforeNick.length >= 2 && this.credentials.beforeNick.length <= 10) {
          this.isValid.validateNicknamelength = true
          console.log('길이는 맞아~')
          // this.$store.state.userInfo.nickname = el.target.value // 한글 입력 이슈 해결하기 위해 사용. 한박자 느린거?
          axios({
            method: 'get',
            url: '/api/register/checkByNickname/' + this.credentials.beforeNick,
            })
            .then(() => { //중복 닉네임 없는 경우
              this.isValid.validateNicknamecheck = true
              console.log('중복없다~')
            })
            .catch(() => { //중복 닉네임 있는 경우
              this.isValid.validateNicknamecheck = false
              console.log('중복있어')
          })
        }
        else {
          this.isValid.validateNicknamelength = false
          console.log('길이가 안맞다~')
        }
      }
    },
    
    async user_change() {
      let nicknameChange = false
      if (this.credentials.beforeNick !== this.$store.state.userInfo.nickname) {
        console.log(this.isValid.validateNicknamecheck)
        console.log(this.isValid.validateNicknamelength)
        if (this.isValid.validateNicknamecheck == true && this.isValid.validateNicknamelength == true) {
          nicknameChange = true
        }
        else {
          this.$store.commit('nicknameErrModalActivate')
        }
      }
      
      // 비번 변경하려 했을 경우
      let pwChange = false
      if (this.credentials.pwConf) {
        if (this.isValid.validateNextPw && this.isValid.validatePwConf) {
          pwChange = true
        }
        else {
          this.$store.commit('pwchangeErrModalActivate')
        }
      }

      else {
        this.$store.dispatch('updateuser', null)
        this.$router.go(-1)
      }


      if (nicknameChange && pwChange){
        this.$store.state.userInfo.nickname = this.credentials.beforeNick
        this.$store.dispatch('updateuser', this.credentials.pwConf)
        .then(() => {
          this.$store.commit('pwchangeConfirmModalActivate')
        })
      }
      else if (nicknameChange){
        this.$store.state.userInfo.nickname = this.credentials.beforeNick
        this.$store.dispatch('updateuser', null)
        .then(() => {
          this.$router.push({path: '/main'})
        })
      }
      else if (pwChange){
        this.$store.dispatch('updateuser', this.credentials.pwConf)
        .then(() => {
          this.$store.commit('pwchangeConfirmModalActivate')
        })
      }
      this.$store.dispatch('updateuser', null)
    },
    pw_change() {
      if (this.pwActivate === false) {
        this.pwActivate = true
        console.log(this.pwActivate)
      }
      else {
        this.pwActivate = false
        this.credentials.nextPw = null
        this.credentials.pwConf = null
        console.log(this.pwActivate)
      }
    },
  },
  created() {
    console.log(this.$store.state.userInfo)
    this.credentials.beforeNick = this.$store.state.userInfo.nickname
  },
   mounted(){
    this.$store.commit('load', false)
  }
}
</script>

<style scoped>
  label {
    color: black;
    font-weight: bold;
    margin-left: 0.5rem;
    font-size: 1.5rem;
		margin-right: auto;
		margin-bottom: 0.5rem;
  }
	#introduce {
		color: black;
    font-weight: bold;
    margin-left: 0.5rem;
    font-size: 1.5rem;
		margin-right: auto;
		margin-bottom: 0.5rem;
	}

  #nickname {
    border: 2px #5E39B3 solid;
    border-radius: 30px;
    width: 95%;
    min-width: 300px;
    height: 5vh;
    min-height: 40px;
    padding: 0.75rem;
    font-size: 3.5rem;
    letter-spacing: -1px;
    font-weight: bold;
		margin-left: 1rem;
  }

  #intro {
    border: 2px #5E39B3 solid;
    border-radius: 30px;
    width: 95%;
    min-width: 300px;
    height: 5vh;
    min-height: 40px;
    padding: 0.75rem;
    font-size: 3.5rem;
    letter-spacing: -1px;
    font-weight: bold;
		margin-left: 1rem;
  }

  #password {
    border: 2px #5E39B3 solid;
    border-radius: 30px;
    width: 95%;
    min-width: 300px;
    height: 5vh;
    min-height: 40px;
    padding: 0.75rem;
    font-size: 3.5rem;
    letter-spacing: -1px;
    font-weight: bold;
		margin-left: 1rem;
  }

  #still {
    border: 2px gainsboro solid;
    border-radius: 30px;
    width: 95%;
    min-width: 300px;
    height: 5vh;
    min-height: 40px;
    padding: 0.75rem;
    font-size: 1.2rem;
    letter-spacing: -1px;
		margin-left: 1rem;
    cursor: not-allowed;
  }
  
  #change {
    border: 2px #5E39B3 solid;
    border-radius: 30px;
    width: 95%;
    min-width: 300px;
    height: 5vh;
    min-height: 40px;
    padding: 0.75rem;
    font-size: 1.2rem;
    letter-spacing: -1px;
		margin-left: 1rem;
  }

  #nickname:focus {
    outline: none;
    background-color: #afa0d6;
    color: white;
    text-shadow: 0 1px 2px rgb(0, 0, 0, 0.5);
  }
  #intro:focus {
    outline: none;
    background-color: #afa0d6;
    color: white;
    text-shadow: 0 1px 2px rgb(0, 0, 0, 0.5);
  }
  #password:focus {
    outline: none;
    background-color: #afa0d6;
    color: white;
    text-shadow: 0 1px 2px rgb(0, 0, 0, 0.5);
  }
  #change:focus {
    outline: none;
    background-color: #afa0d6;
    color: white;
    text-shadow: 0 1px 2px rgb(0, 0, 0, 0.5);
  }
  #still:focus {
    outline: none;
    background-color: #afa0d6;
    color: white;
    text-shadow: 0 1px 2px rgb(0, 0, 0, 0.5);
  }

  #nickname::placeholder {
    font-size: 1.1rem !important;
    font-weight: initial;
    text-shadow: none;
    position: absolute;
    top: 18%;
  }
  #nickname:focus::placeholder {
    color: transparent;
  }

  #intro::placeholder {
    font-size: 1.1rem !important;
    font-weight: initial;
    text-shadow: none;
    position: absolute;
    top: 18%;
  }
  #intro:focus::placeholder {
    color: transparent;
  }

  #password::placeholder {
    font-size: 1.1rem !important;
    font-weight: initial;
    text-shadow: none;
    position: absolute;
    top: 18%;
  }
  #password:focus::placeholder {
    color: transparent;
  }

  #still::placeholder {
    font-size: 1.1rem !important;
    font-weight: initial;
    text-shadow: none;
    position: absolute;
    top: 18%;
  }
  #still:focus::placeholder {
    color: transparent;
  }

  #change::placeholder {
    font-size: 1.1rem !important;
    font-weight: initial;
    text-shadow: none;
    position: absolute;
    top: 18%;
  }
  #change:focus::placeholder {
    color: transparent;
  }
	
	textarea {
		border: 2px #5E39B3 solid;
    border-radius: 20px;
    width: 95%;
    min-width: 300px;
    min-height: 40px;
    padding: 0.75rem;
    font-size: 1rem;
    letter-spacing: -1px;
    font-weight: bold;
		margin-left: 1rem;
	}
	textarea:focus {
    outline: none;
    background-color: #afa0d6;
    color: white;
    text-shadow: 0 1px 2px rgb(0, 0, 0, 0.5);
  }
	textarea::placeholder {
    font-size: 1.1rem !important;
    font-weight: initial;
    text-shadow: none;
    position: absolute;
    top: 18%;
  }

  textarea:focus::placeholder {
    color: transparent;
  }
	#nickname {
		font-size: 1rem;
		letter-spacing: -1px;
    font-weight: bold;
	}
  h1 {
    font-size: 2.8rem;
    font-weight: bold;
    margin-bottom: 3rem;
  }
	#profile_head{
		display: flex;
		flex-direction: row;
	}

	#profile_img {
		width:130px;
		height: 130px;
		border-radius: 130px;
    margin-left: 0.5rem;		
	}

	#user_id {
		text-align: right;
		font-size: 1.8rem;
		font-weight: bold;
		margin-top: auto;
		margin-bottom: auto;
		margin-left: 1rem;
	}
	#profile_img_change {
		margin-left:auto;
		margin-top: auto;

	}

	#profile_img_change_button {
		background-color: #5E39B3;
    color: white;
		width: 6.9rem;
		height: 2rem;
		font-size: 1rem;
		font-weight: bold;
		border-radius: 30px;
		border: none;
	}

  #pu_form {
    text-align: left;
  }
  
  #pu_form_radio {
    text-align: left;
  }

  #check_radio {
    display: flex;
    justify-content: left;
    align-items: flex-start;
    width: 100%;
    min-width: 300px;
    height: 5vh;
    min-height: 40px;
    padding: 0.75rem;
    font-size: 3.5rem;
    letter-spacing: -1px;
    font-weight: bold;
    margin-top: 1rem;
    margin-left: 1rem;
  }

  #on {
    display: flex;
    width: 39%;
  }

  #off {
    display: flex;
    width: 39%;
  }

  h3 {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
  }

  h5 {
    font-size: 1.2rem;
  }

  p {
    margin: 0 0.5rem;
  }

  #pu_button {
    background-color: #5E39B3;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: none;
    border-radius: 30px;
    width: 7rem;
    height: 3rem;
    margin: 1rem;
  }

  .warn {
    color: rgb(240, 90, 90);
  }

  .collect {
    color: green;
  }

  #pu_container {
    width: 85%;
    margin: 0 auto;
  }

  #pu_header {
		text-align: left;
    margin: 3rem 1rem;
  }

  #pu_body {
    width: 80%;
    margin: auto;
  }

  #pu_body a {
		display:flex;
		justify-content: right;
		margin-right: 0.5rem;
    text-decoration: none;
    color: rgb(85, 85, 255);
    font-size: 1.125rem;
    font-weight: bold;
    cursor: pointer;
  }

  #pu_buttons {
    display: flex;
    flex-direction: row !important;
    justify-content: space-evenly;
    margin-bottom: 2rem;
    /* margin: auto; */
    /* margin: 1rem 4rem 1rem; */
  }

  #pwchange {
    display: flex;
    justify-content: center;
    width: 40%;
  }

  #pwactive {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  #user_email {
    font-weight: bold;
    font-size: 1.25rem;
    color: #504f4f;
    margin-top: auto;
    margin-bottom: auto;

  }
  #user_birth {
    font-weight: bold;
    font-size: 1.25rem;
    color: #504f4f;
    margin-top: auto;
    margin-bottom: auto;
  }
  #withdrawal {
    background-color: crimson;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: none;
    border-radius: 30px;
    width: 7rem;
    height: 3rem;
    margin: 1rem;
  }
</style>