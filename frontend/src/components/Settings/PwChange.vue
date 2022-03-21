<template>
  <div id="pc_container">
    <section id="pc_header">
      <h1>비밀번호 변경</h1>
      <h3>계정 보호를 위해 주기적으로</h3>
      <h3>비밀번호를 교체해주세요</h3>
    </section>
    <section id="pc_body">
      <article id="before_pw_form">
        <label for="before_pw">비밀번호</label>
        <input type="password" 
        id="before_pw"
        v-model="credentials.beforePw"
        placeholder="사용중인 비밀번호를 입력해주세요.">
        <span v-if="credentials.beforePw">
          <p v-if="credentials.beforePw === this.$store.state.userInfo.pw" class="collect">
            현재 비밀번호와 일치합니다.
          </p>
          <p v-if="credentials.beforePw !== this.$store.state.userInfo.pw" class="warn">
            비밀번호가 맞지 않아요.
          </p>
        </span>
      </article>
      <article id="next_pw_form">
        <label for="next_pw">변경할 비밀번호</label>
        <input type="password" 
        id="next_pw"
        v-model="credentials.nextPw"
        @input="pwCheck"
        placeholder="비밀번호는 8자 이상, 20자 이하입니다.">
        <span v-if="credentials.nextPw">
          <p v-if="!isValid.validateNextPw" class="warn">
            사용할 수 없는 비밀번호에요.
          </p>
          <p v-if="isValid.validateNextPw" class="collect">
            사용할 수 있는 비밀번호입니다.
          </p>
        </span>
      </article>
      <article id="pw_conf_form">
        <label for="pw_conf">비밀번호 확인</label>
        <input type="password" id="pw_conf"
        v-model="credentials.pwConf"
        @input="pwConfCheck"
        placeholder="비밀번호를 다시 입력해주세요.">
        <span v-if="credentials.pwConf">
          <p v-if="!isValid.validatePwConf" class="warn">
            비밀번호가 맞지 않아요.
          </p>
          <p v-if="isValid.validatePwConf" class="collect">
            비밀번호가 일치합니다.
          </p>
        </span>
      </article>
      <article id="pin-form">
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
      </article>
      <a @click="pwFind">비밀번호를 잊었나요?</a>
      <article id="pc_buttons">
        <button @click="changePw">변경하기</button>
        <button @click="go_to_back">뒤로가기</button>
      </article>
    </section>
  </div>
</template>

<script>
export default {
  data: function(){
    return {
      credentials : {
        beforePw: null,
        nextPw: null,
        pwConf: null
      },
      isValid: {
        validateNextPw: false,
        validatePwConf: false,
      },
      help: false
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
    pwFind(){
      this.$router.push('/setting/password-find')
    },
    go_to_back: function(){
      this.$router.go(-1)
    },
    changePw() {
      // 처음 입력한 값이랑 유저 비밀번호랑 같고, 변경할 비밀번호 입력값이랑 변경 비밀번호 확인값이랑 같으면
      if (this.credentials.beforePw === this.$store.state.userInfo.pw && this.credentials.nextPw === this.credentials.pwConf) {
        this.$store.dispatch('changePw', this.credentials.nextPw)
      }
    },
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
    font-size: 4rem;
    letter-spacing: -1px;
    font-weight: bold;
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

  .warn {
    color: rgb(240, 90, 90);
  }

  .collect {
    color: green;
  }

  #pc_container {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 80%;
    margin: 0 auto;
  }

  #pc_header {
    display: flex;
    flex-direction: column;
    align-self: flex-start;
    align-items: flex-start;
    margin: 2rem 1rem;
  }

  #pc_body {
    display: flex;
    flex-direction: column;
    /* align-items: center; */
    width: 80%;
    margin: 1rem;
  }

  #pc_body article {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    padding: 1rem 0;
    width: 100%;
  }

  #pc_body a {
    align-self: flex-end;
    text-decoration: none;
    color: rgb(85, 85, 255);
    font-size: 1.125rem;
    font-weight: bold;
    margin: 1rem 0;
    cursor: pointer;
  }

  #pc_buttons {
    display: flex;
    flex-direction: row !important;
    justify-content: center;
    margin: 1rem;
  }

  #pc_buttons > *:last-child {
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