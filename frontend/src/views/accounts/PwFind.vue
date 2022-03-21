<template>
  <div id="pf-container">
    <section id="pf-header">
      <h1>비밀번호 찾기</h1>
      <h3>비밀번호를 잊으셨군요</h3>
      <h3>임시 비밀번호를 보내드릴게요</h3>
    </section>
    <section id="pf-body">
      <article id="email-form">
        <div id="email-form-header">
          <label for="email">이메일</label>
          <span v-show="credentials.email">
            <input type="checkbox" id="checkbox" v-model="checked">
            <label for="checkbox">여기로 받을게요</label>
          </span>
        </div>
        <input type="email" 
        id="email"
        v-model="credentials.email"
        @input="emailInput"
        placeholder="등록하신 이메일을 입력해주세요.">
      </article>
      <article id="te-form">
        <label for="target-email">전달받을 이메일</label>
        <input type="text" id="target-email"
        v-model="credentials.target_email"
        :disabled="checked" :class="{'disabled':checked }"
        placeholder="임시 비밀번호를 받을 이메일을 입력해주세요.">
      </article>
      <article id="tel-form">
        <label for="tel">휴대전화</label>
        <input type="text" id="tel"
        v-model="credentials.tel"
        @input="tel_helper" maxlength="13"
        @keyup.enter="send_mail"
        placeholder="등록하신 휴대전화를 입력해주세요.">
        <span v-if="credentials.tel">
          <p v-if="!isValid.validateTel" class="warn">
            번호가 이상해요...
          </p>
          <p v-if="isValid.validateTel" class="collect">
            가능한 번호예요!
          </p>
        </span>
      </article>
      <!-- <article id="pin-form">
        <span>
          <label for="pin">PIN 번호</label>
          <img src="../../assets/images/icons/help.png" alt="help" id="help"
          @mouseover="help = true" @mouseout="help = false">
          <p v-show="help" id="help-message">
            PIN 번호는 회원 가입시 설정한 추가 비밀번호입니다.
            PIN 번호를 분실하였을 경우 고객센터 문의를 이용해주세요.
          </p>
        </span>
        <input type="password" id="pin"
        v-model="credentials.pin"
        placeholder="등록하신 PIN 번호를 입력해주세요.">
      </article> -->
      <router-link :to="{ name: 'EmailFind' }">이메일을 잊었나요?</router-link>
      <article id="pf-buttons">
        <button @click="send_mail">메일 받기</button>
        <button @click="go_to_back">뒤로가기</button>
      </article>
    </section>
  </div>
</template>

<script>
import { mapState } from 'vuex'
import axios from 'axios'
export default {
  data: function(){
    return {
      credentials : {
        email: null,
        target_email: null,
        tel: null,
        pin: null
      },
      isValid: {
        validateEmail: false,
        validateTel: false,
      },
      checked: false,
      help: false
    }
  },
  methods: {
    send_mail(){
      this.$store.commit('load', true)
      let data = {
        email: this.credentials.email,
        tel: this.credentials.tel,
        requestemail : this.credentials.target_email,
      };
      axios({
          method: 'post',
          url: '/api/register/findPw',
          data: data, 
        }).then((res) => {
        console.log("메일 전송 성공" , res)
        //  alert("매일을 확인해 주세요.")
        this.$store.commit('load', false)
        this.$store.commit('wrongEmailModalActivate')
        }).then(()=>{
          this.$router.push("/login")
        }).catch((error) => {
          // alert("일치하는 정보가 없습니다.")
          this.$store.commit('noMatchEmailModalActivate')
          console.log(error);
        })
        .finally(() => this.$store.commit('load', false))
      },

    emailInput(){
      if (!this.credentials.email){
        console.log('-1')
        this.credentials.target_email = null
        this.checked = false
      }
    },
    go_to_back: function(){
      this.$router.go(-1)
    },
    tel_helper: function(event){
      const nums = this.credentials.tel.length
      const n = this.credentials.tel.charCodeAt(nums-1)
      const poss = ['010', '011', '012', '013', '014',
                    '015', '016', '017', '018', '019']
      if (event.inputType == 'deleteContentBackward'){
        if (nums == 3 || nums == 8){
          this.credentials.tel = this.credentials.tel.slice(0, nums - 1)
        }
        return
      }
      if (n > 47 && n < 58){
        if (nums == 3 || nums == 8){
          this.credentials.tel += '-'
        }
      }
      else {
        this.credentials.tel = this.credentials.tel.slice(0, nums - 1)
      }
      if (nums == 13 && poss.indexOf(this.credentials.tel.slice(0,3)) > -1){
        this.isValid.validateTel = true
      }
      else {
        this.isValid.validateTel = false
      }
    },
  },
  computed: mapState(['user']),
  watch: {
    checked(){
      if (this.checked){
        this.credentials.target_email = this.credentials.email
      }
      else {
        this.credentials.target_email = null
      }
    }
  },
  mounted(){
    this.$store.commit('load', false)
  }
}
</script>

<style scoped>
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
    letter-spacing: -1px;
    font-weight: bold;
  }

  input[type="checkbox"] {
    width: 1rem;
    height: 1rem;
    min-width: 10px;
    min-height: 10px;
    padding: 0;
    margin: 0;
  }

  input[type="password"] {
    font-size: 4rem;
  }

  input:focus {
    outline: none;
    background-color: #afa0d6;
    color: white;
    text-shadow: 0 1px 2px rgb(0, 0, 0, 0.5);
  }

  input::placeholder {
    font-size: 1.25rem !important;
    font-weight: initial;
    text-shadow: none;
    position: absolute;
    top: 18%;
  }

  input:focus::placeholder {
    color: transparent;
  }

  h1 {
    font-size: 2.5rem;
    font-weight: bold;
    margin-bottom: 4rem;
  }

  h3 {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
  }

  p {
    margin: 0 0.5rem;
  }

  button {
    background-color: #5E39B3;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: none;
    border-radius: 20px;
    padding: 0.4rem 1.5rem;
    margin: 1rem 2rem 1rem 0;
    cursor: pointer;
    line-height: 2rem;
  }

  #email-form-header span label {
    color: black;
    font-size: 1rem;

  }

  .warn {
    color: rgb(240, 90, 90);
  }

  .collect {
    color: green;
  }

  .disabled {
    background-color: #cccccc;
  }

  #pf-container {
    background-color: white;
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 600px;
    min-height: 92.5vh;
    /* height: 100%; */
    padding: 2rem;;
    border-radius: 20px;
    border: 2px  #5E39B3 solid;
    /* border-radius: 20px;
    border: 2px  #5E39B3 solid; */
  }

  #pf-header {
    display: flex;
    flex-direction: column;
    align-self: flex-start;
    align-items: flex-start;
    margin: 2rem 1rem;
  }

  #pf-body {
    display: flex;
    flex-direction: column;
    width: 80%;
    margin: 1rem;
  }

  #pf-body article {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    padding: 1rem 0;
    width: 100%;
  }

  #email-form-header {
    display: flex;
    justify-content: space-between;
    width: 100%;
  }

  #email-form-header span {
    display: flex;
    align-items: center;
  }

  #pf-body a {
    align-self: flex-end;
    text-decoration: none;
    color: rgb(85, 85, 255);
    font-size: 1.125rem;
    font-weight: bold;
    margin: 1rem 0;
  }

  #pf-buttons {
    display: flex;
    flex-direction: row !important;
    justify-content: center;
    margin: 1rem;
  }

  #pf-buttons > *:last-child {
    background-color: #777777;
  }

  #pin-form span {
    display: flex;
    align-items: center;
    position: relative;
  }

  #help {
    width: 1rem;
    height: 1rem;
    margin: 0 0.5rem;
  }

  #help-message {
    font-size: 0.75rem;
    width: 15rem;
    position: absolute;
    top: 80%;
    left: 75%;
    background-color: #5E39B3;
    color: white;
    z-index: 1;
    padding: 1rem;
    border-radius: 20px;
    word-break: keep-all;
  }
</style>
