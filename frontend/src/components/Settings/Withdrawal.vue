<template>
  <div id="wd_container">
    <div id="inner_container">
      <section id="wd_header">
        <h1>회원 탈퇴</h1>
        <h3>이별의 시간은 언제나 슬퍼요..</h3>
        <h3>다시 볼 수 있길 바랄게요 😢</h3>
        <h4>회원 탈퇴를 위해 비밀번호를 입력해주세요</h4>
      </section>
      <section id="wd_body">
        <article id="pw_form">
          <label for="pw">비밀번호</label>
          <input type="password" id="pw"
          v-model="credentials.pw"
          placeholder="비밀번호를 입력해주세요.">
          <!-- <span v-if="credentials.pw">
            <p v-if="!isValid.validatePw" class="warn">
              사용할 수 없는 비밀번호에요.
            </p>
            <p v-if="isValid.validatePw" class="collect">
              사용할 수 있는 비밀번호입니다.
            </p>
          </span> -->
        </article>
        <article id="pwConf_form">
          <label for="pwConfn">비밀번호 확인</label>
          <input type="password" id="pwConf"
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
        <article id="pc_buttons">
          <button @click="activate = true">회원탈퇴</button>
          <button @click="go_to_back">뒤로가기</button>
        </article>
      </section>
      <wd-conf v-if="activate" @cancel="activate = false" />
    </div>
  </div>
</template>

<script>
import wdConf from '@/components/Settings/WithdrawalConf'

export default {
  data: function(){
    return {
      credentials: {
        pw: null,
        pwConf: null
      },
      isValid: {
        validatePwConf: false
      },
      activate: false
    }
  },
  components: {
    wdConf
  },
  methods: {
    pwConfCheck: function(){
      if (this.credentials.pwConf && this.credentials.pw === this.credentials.pwConf){
        this.isValid.validatePwConf = true
      }
      else {
        this.isValid.validatePwConf = false
      }
    },
    go_to_back: function(){
      this.$router.push('/setting')
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

  h4 {
    font-size: 1.5rem;
    margin-top: 3rem;
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
  #wd_container {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  #inner_container {
    width: 85%;
    margin-left: auto;
    margin-right: auto;
    margin-top: 1rem;
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  #wd_header {
    display: flex;
    flex-direction: column;
    align-self: flex-start;
    align-items: flex-start;
    margin: 2rem;
  }

  #wd_body {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 80%;
  }

  #wd_body article {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    padding-bottom: 3rem;
    width: 100%;
  }

  #pc_buttons {
    display: flex;
    flex-direction: row !important;
    justify-content: center;
    margin-top: 2rem;
  }

  #pc_buttons > *:first-child {
    background-color: rgb(240, 90, 90);
  }
</style>