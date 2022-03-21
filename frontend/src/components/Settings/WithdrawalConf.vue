<template>
  <div id="wdc_container">
    <section id="wdc_modal">
      <article id="wdc_header">
        <span id="go_to_back" @click="go_to_back" />
        <h3>회원 탈퇴</h3>
      </article>
      <article v-if="!confirm" class="wdc_content">
        <div class="wdc_body">
          <h4>정말 떠나시는건 아니겠죠?😭</h4>
          <h4><span style="color: red;">시민권</span>은 삭제되며 복구할 수 없습니다</h4>
        </div>
        <div class="wdc_buttons">
          <button @click="go_to_back">아니요</button>
          <button @click="confirm = true">네, 탈퇴합니다.</button>
        </div>
      </article>
      <article v-if="confirm" class="wdc_content">
        <div class="wdc_body">
          <h4>회원 탈퇴가 완료되었습니다.</h4>
          <h4>다시 만날 수 있으면 좋겠어요.</h4>
        </div>
        <div class="wdc_buttons">
          <button @click="go_to_back">확인</button>
        </div>
      </article>
    </section>
  </div>
</template>

<script>
import axios from 'axios'

const session = window.sessionStorage;

export default {
  data: function(){
    return {
      confirm: false
    }
  },
  methods: {
    go_to_back: function(){
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
       axios({
        method: 'delete',
        url: '/api/users/' + this.$store.state.userInfo.no,
        headers: headers,
        })
			.then(() => {
				console.log('탈퇴');
				session.clear();
			})
			.then(() => {
				window.location.reload()
			})
			.catch(() => alert('fail'))
    this.$emit('cancel')
    }
  }
}
</script>

<style scoped>
  h3 {
    font-weight: bold;
    margin: 0;
  }
  h4 {
    font-size: 1.4rem;
    font-weight: bold;
  }
  p {
    font-size: 1.125rem;
    font-weight: bold;
    margin: 0;
  }

  button {
    background-color: #5E39B3;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: none;
    border-radius: 20px;
    padding: 0.2rem 1rem;
    margin: 0.5rem;
    cursor: pointer;
    line-height: 2rem;
  }

  #wdc_container {
    display: flex;
    justify-content: center;
    align-items: center;
    position: fixed;
    width: 100%;
    height: 100%;
    top: 0;
    left: 0;
    background-color: rgb(0, 0, 0, 0.5);
  }

  #wdc_modal {
    display: flex;
    flex-direction: column;
    background-color: white;
    border-radius: 20px;
    width: 26rem;
    min-width: 300px;
    height: 20rem;
    min-height: 230px;
  }

  #wdc_header {
    display: flex;
    justify-content: center;
    height: 3.5rem;
    border-bottom: 1px #cccccc solid;
    padding: 0.25rem;
    position: relative;
  }

  #wdc_header span {
    width: 2rem;
    height: 2rem;
    background-image: url('../../assets/images/icons/return.png');
    background-size: cover;
    background-repeat: no-repeat;
    position: absolute;
    top: 10%;
    left: 2%;
    cursor: pointer;
  }

  .wdc_content {
    display: flex;
    flex-direction: column;
    height: 90%;
  }

  .wdc_body {
    display: flex;
    flex-direction: column;
    /* align-items: flex-start; */
    text-align: center;
    justify-content: center;
    border-bottom: 1px #cccccc solid;
    padding: 1.5rem;
    height: 80%;
  }

  .wdc_buttons {
    display: flex;
    justify-content: flex-end;
    padding: 0.5rem;
  }

  .wdc_buttons > *:last-child {
    background-color: #777777;
  }
</style>
