<template>
  <div id="signup_container">
    <div id="moreinfo_innercontainer">
      <section id="signup_header">
        <h1 style="font-size: 2.5rem;"> 앗!</h1>
        <span id="signup_header_title">
          <h1 style="color: #5E39B3; font-size: 2.5rem;">당신의 여행티켓</h1>
          <h1>에 </h1>
        </span>
        <h1 style="font-size: 2.5rem;">갱신절차가 필요해요👽</h1>
      </section>
      <section id="signup_form">
        <article id="email_form">
          <label for="email">이메일</label>
          <input type="email"
          id="email"
          v-model="this.$store.state.userInfo.email"
          autocomplete="off"
          readonly>
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
            <p v-if="!isValid.validateNicknamecheck" class="warn">
              사용중인 닉네임이에요.
            </p>
            <p v-if="isValid.validateNicknamecheck" class="collect">
            사용가능한 닉네임입니다.
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
          <button @click="signup" id="signup_btn">여행티켓 등록하기</button>
          <button @click="go_to_back" id="back_to_btn">다음에 할게요</button>
        </article>
      </section>
    </div>
  </div>
</template>


<script>
const clear = function(){
  window.sessionStorage.clear()
  return new Promise(resolve => resolve(true))
}

// 소셜로그인 최초로 했을 때 추가 정보(전화번호, 닉네임, 생년월일) 받는 페이지
  import axios from 'axios'
  const session = window.sessionStorage
  export default {
    name: 'MoreInfo',
    data: function () {
      return {
        maxdate: null,
        credentials: {
          nickname: null,
          tel: null,
          birth: null,
        },
        isValid: {
          validateNicknamecheck : false, // 중복 닉네임 여부
          validateTel: false // 휴대전화 중복 여부
        },
      }
    },
    methods: {
      signup: function () {
        this.$store.state.userInfo.nickname = this.credentials.nickname
        this.$store.state.userInfo.tel = this.credentials.tel
        this.$store.state.userInfo.birth = this.credentials.birth
        const body = { no: this.$store.state.userInfo.no, nickname: this.credentials.nickname, tel: this.credentials.tel, birth: this.credentials.birth  }
        let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
      axios({
        method: "put",
        url: "/api/users/update",
        data: body,
        headers: headers,
      })
        .then((res) => {
          console.log("업데이트 성공")
          this.$store.dispatch('allTokenRefreshOnUserInfo', res)
          this.$store.commit('moreInfoConfirmModalActivate')
        })
        .catch((err) => {
          console.log("업데이트 실패", err)
          //  this.$store.commit('signupFailModalActivate1', err.response.data.message)
        });
      },
      checkNickname: function(el){
        this.credentials.nickname = el.target.value // 한글 입력 이슈 해결하기 위해 사용. 한박자 느린거?
        axios({
          method: 'get',
          url: '/api/register/checkByNickname/' + this.credentials.nickname,
          })
          .then(() => { //중복 닉네임 없는 경우
            this.isValid.validateNicknamecheck = true
          })
          .catch(() => { //중복 닉네임 있는 경우
            this.isValid.validateNicknamecheck = false
        })
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
          console.log(res)
          if (res.data){
            this.isValid.validateTel = true
          }
          else {
            this.isValid.validateTel = false
          }
        })
      },
      go_to_back: async function(){
        await clear()
        console.log(window.sessionStorage)
        this.$router.go(-1)
      }
    },
    created(){
      var today = new Date();
      var year = today.getFullYear();
      var month = ('0' + (today.getMonth() + 1)).slice(-2);
      var day = ('0' + today.getDate()).slice(-2);
      this.maxdate = year + '-' + month  + '-' + day;
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
    border-radius: 20px;
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
  }
  #moreinfo_innercontainer{
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
    padding: 2rem;
    overflow: unset;
  }

  #signup_form h1, article {
    margin-bottom: 1rem;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    width: 100%
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