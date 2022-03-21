<template>
  <div id="signup_container">
    <div id="signup_innercontainer">
      <section id="signup_header">
        <h1 style="font-size: 2.5rem;">어서오세요!</h1>
        <span id="signup_header_title">
          <h1 style="color: #5E39B3; font-size: 2.5rem;">이모션 플래닛</h1>
          <h1 style="font-size: 2.5rem;">에</h1>
        </span>
        <h1 style="font-size: 2.5rem;">여행할 수 있는 티켓을 발급해볼까요?👽</h1>
      </section>
      <section id="signup_form">
        <article id="email_form">
          <label for="email">이메일</label>
          <input type="email"
          id="email"
          v-model="credentials.email"
          placeholder="사용중인 이메일을 입력해주세요."
          autocomplete="off"
          @input = "validateEmail">
          <span v-if="credentials.email && !isValid.validateEmailcheck">
            <p v-if="isValid.validateEmail" class="warn">
              사용중인 이메일이에요.
            </p>
            <p v-if="!isValid.validateEmail" class="warn">
              이메일 형식에 맞춰주세요. 
            </p>
          </span>
          <span v-if="credentials.email && isValid.validateEmailcheck" class="collect">
            <p>
              사용가능한 이메일입니다.
            </p>
          </span>
        </article>
        <article id="nickname_form">
        <label for="nickname">닉네임</label>
        <input type="text"
        id="nickname"
        v-model="credentials.nickname"
        placeholder="닉네임은 2자 이상, 10자 이하입니다."
        autocomplete="off" maxlength="10"
        @input= "checkNickname">
        <span v-if="credentials.nickname">
          <p v-if="!isValid.validateNicknamelength" class="warn">
            닉네임은 2자 이상, 10자 이하입니다.
          </p>
          <p v-if="!isValid.validateNicknamecheck && isValid.validateNicknamelength" class="warn">
            사용중인 닉네임이에요.
          </p>
          <p v-if="isValid.validateNicknamecheck && isValid.validateNicknamelength" class="collect">
           사용가능한 닉네임입니다.
          </p>
        </span>
      </article>
      <article id="pw_form">
        <label for="pw">비밀번호</label>
        <input type="password" 
        id="pw" maxlength="20"
        v-model="credentials.pw"
        @input="pwCheck"
        placeholder="비밀번호는 8자 이상, 20자 이하입니다.">
        <span v-if="credentials.pw">
          <p v-if="!isValid.validatePw" class="warn">
            사용할 수 없는 비밀번호에요.
          </p>
          <p v-if="isValid.validatePw" class="collect">
            사용할 수 있는 비밀번호입니다.
          </p>
        </span>
      </article>
      <article id="passwordConfirmation_form">
        <label for="passwordConfirmation">비밀번호 확인</label>
        <input type="password"
        id="passwordConfirmation" maxlength="20"
        v-model="credentials.passwordConfirmation"
        @input="pwConfCheck"
        placeholder="비밀번호를 다시 입력해주세요.">
        <span v-if="credentials.passwordConfirmation">
          <p v-if="!isValid.validatePwConf" class="warn">
            비밀번호가 맞지 않아요.
          </p>
          <p v-if="isValid.validatePwConf" class="collect">
            비밀번호가 일치합니다.
          </p>
        </span>
      </article>
      <article id="tel_form">
        <label for="tel">휴대전화</label>
        <input type="text"
        id="tel"
        v-model="credentials.tel"
        placeholder="사용중인 전화번호를 입력해주세요."
        autocomplete="off" maxlength="13"
        @input= "tel_helper">
        <span v-if="credentials.tel">
          <p v-if="!isValid.validateTel" class="warn">
            사용 불가능한 전화번호에요.
          </p>
          <p v-if="isValid.validateTel" class="collect">
            사용가능한 전화번호입니다.
          </p>
        </span>
      </article>
      <article id="birth_form">
        <label for="birth">생년월일</label>
        <input type="date" id="birth" v-model="credentials.birth" :max="this.maxdate">
      </article>
        <article id="btn_container">
          <button @click="signup" id="signup_btn">여행티켓 발급하기</button>
          <button @click="go_to_back" id="back_to_btn">다음에 할게요</button>
        </article>
      </section>
    </div>
  </div>
</template>


<script>
// 회원가입 완료 후 로그인 페이지로 이동하게 만들어야 함
  import axios from 'axios'

  export default {
    name: 'Signup',
    data: function () {
      return {
        maxdate: null,
        credentials: {
          email: null,
          nickname: null,
          pw: null,
          passwordConfirmation: null,
          tel: null,
          birth: null,
        },
        isValid: {
          validateEmail: false, // 이메일 형식 체크
          validateEmailcheck : false, // 중복 이메일 여부
          validateNicknamecheck : false, // 중복 닉네임 여부
          validateNicknamelength: false, // 닉네임 길이 체크
          validatePw: false, // 비밀번호 길이 체크
          validatePwConf: false, // 비밀번호와 비밀번호 확인 일치 여부
          validateTel: false // 휴대전화 중복 여부
        },
      }
    },
    computed: {
      canIJoin1(){
        let temp = true
        for (let key in this.isValid){
          if (!this.isValid[key]){
            temp = false
          }
        }
        return temp
      },
      canIJoin2(){
        let temp = true
        for (let key in this.credentials){
          if (!this.credentials[key]){
            temp = false
          }
        }
        return temp
      }
    },
    created(){
      var today = new Date();
      var year = today.getFullYear();
      var month = ('0' + (today.getMonth() + 1)).slice(-2);
      var day = ('0' + today.getDate()).slice(-2);
      this.maxdate = year + '-' + month  + '-' + day;
    },
    methods: {
       validateEmail: function(){
        let regexp =
        /^[0-9a-zA-Z]([-.]?[0-9a-zA-Z])*@[0-9a-zA-Z]([-.]?[0-9a-zA-Z])*\.[a-zA-Z]{2,3}$/i;
        this.isValid.validateEmail = regexp.test(this.credentials.email) ? true : false; //이메일 형식에 맞으면 true 아니면 false
        if(this.isValid.validateEmail){ //현재 이메일이 이메일 형식에 맞다면 중복검사 하러감
          this.checkEmail()
        }
        else{ //현재 이메일이 이메일 형식에 맞지 않다면 중복 이메일 여부를 false로 둠 => true값으로 변경됬을경우를 대비
          this.isValid.validateEmailcheck = false
        }
      },
      signup: function () {
        if (this.canIJoin1 && this.canIJoin2){ // 입력 비밀번호가 일치하면 회원가입 (나중에 여기다 벨류체크)
          axios({
            method: 'post',
            url: '/api/register',
            data: this.credentials
          })
          .then( () => {
            this.$store.commit('signupConfirmModalActivate')
            // this.$router.push({name:'Login'}) // 가입 완료시 로그인 페이지로 이동

            // if (alert('가입이 완료되었습니다.')){
            //   this.$router.push({name:'Login'}) // 가입 완료시 로그인 페이지로 이동
            // }
          })
          .catch(res => {
            this.$store.commit('signupFailModalActivate1', res.response.data.message)
            //alert(res.response.data.message) // 서버측에서 넘어온 오류 메시지 출력.
          })
        }
        else {
          this.$store.commit('signupFailModalActivate2')
          // alert('비밀번호를 확인해주세요.')
        }
        this.credentials.email ="";
        this.credentials.nickname="";
        this.credentials.pw = "";
        this.credentials.passwordConfirmation="";
        this.credentials.birth ="";
      },
      checkEmail: function(){
        axios({
          method: 'get',
          url: '/api/register/checkByEmail/' + this.credentials.email,
        })
        .then(() => { //중복 이메일 없는 경우
          this.isValid.validateEmailcheck = true
        })
        .catch(()=> { //중복 이메일 있는 경우
          this.isValid.validateEmailcheck = false
        })
      },
      checkNickname: function(el){
        this.credentials.nickname = el.target.value // 한글 입력 이슈 해결하기 위해 사용. 한박자 느린거?
        if (this.credentials.nickname.length >= 2 && this.credentials.nickname.length <= 10) {
          this.isValid.validateNicknamelength = true
          console.log('길이는 맞아~')
          // this.$store.state.userInfo.nickname = el.target.value // 한글 입력 이슈 해결하기 위해 사용. 한박자 느린거?
          axios({
            method: 'get',
            url: '/api/register/checkByNickname/' + this.credentials.nickname,
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
      },
      pwCheck: function(){
        if (this.credentials.pw && this.credentials.pw.length >= 8 && this.credentials.pw.length <= 20){
          this.isValid.validatePw = true
        }
        else {
          this.isValid.validatePw = false
        }
      },
      pwConfCheck: function(){
        if (this.credentials.passwordConfirmation && this.credentials.pw === this.credentials.passwordConfirmation){
          this.isValid.validatePwConf = true
        }
        else {
          this.isValid.validatePwConf = false
        }
      },
      tel_helper: function(event){
        const nums = this.credentials.tel.length
        const n = this.credentials.tel.charCodeAt(nums-1)
        const poss = ['010', '011', '012', '013', '014',
                      '015', '016', '017', '018', '019']

        console.log(nums)
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
          console.log(poss.indexOf(this.credentials.tel.slice(0,3)))
          console.log(nums)
          this.telCheck()
        }
        else {
          this.isValid.validateTel = false
        }
      },
      telCheck: function(){
        axios({
          method: 'get',
          url: '/api/register/checkByTel/' + this.credentials.tel
        })
        .then(res => {
          console.log('전화번호중복체크',res)
          if (res.data){
            this.isValid.validateTel = true
          }
          else {
            this.isValid.validateTel = false
          }
        })
      },
      go_to_back: function(){
        this.$router.go(-1)
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
    font-size: 1.25rem;
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
    letter-spacing: -1px;
    position: absolute;
    top: 20%;
  }
  input:focus::placeholder {
    color: transparent;
  }

  p {
    margin: 0 0 0 0.5rem;
    font-size: 0.8rem;
  }

  img {
    width: 12vh;
    height: 18vh;
    min-width: 120px;
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

  .warn {
    color: rgb(240, 90, 90);
  }

  .collect {
    color: green;
  }

  #signup_container {
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
    padding: 2rem;;
    border-radius: 20px;
    border: 2px  #5E39B3 solid;
    /* background-color: white;
    width: 30%;
    min-width: 450px;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: center;
    padding: 3rem 2rem 1.5rem;
    border-left: 2px #cccccc solid;
    border-right: 2px #cccccc solid;
    border-radius: 20px;
    border: 2px  #5E39B3 solid;*/
  }
  #signup_innercontainer {
    width: 85%;
    margin-left: auto;
    margin-right: auto;
    margin-top: 1rem;
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  #signup_header {
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    align-items: flex-start;
    align-self: flex-start;
  }

  #signup_header h1 {
    margin: 0;
    font-size: 2rem;
    font-weight: bold;
    letter-spacing: -1px;
  }

  #signup_header_title {
    display: flex;
    flex-wrap: nowrap;
  }

  #signup_form {
    width: 90%;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: center;
    padding: 1.5rem;
    overflow: unset;
  }

  #signup_form h1, article {
    width: 100%;
    margin-bottom: 1rem;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
  }

  #btn_container {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin: 2rem 0 1rem;
  }

  #signup_btn {
    font-size: 1.35rem;
    padding: 0.5rem 2rem;
    width: 25vh;
    min-width: 250px;
  }

  #back_to_btn {
    background-color: #777777;
    font-size: 1.35rem;
    padding: 0.5rem 2rem;
    width: 25vh;
    min-width: 250px;
    margin-bottom: 0;
  }

  ::-webkit-calendar-picker-indicator {
    margin: 0;
  }

  input::-webkit-datetime-edit-day-field:focus,
  input::-webkit-datetime-edit-month-field:focus,
  input::-webkit-datetime-edit-year-field:focus {
    background-color: transparent;
  }
</style>