<template>
	<div id="login_fail">
    <div id="modal">
			<h4>프로필 정보가 성공적으로 변경되었습니다. 다시 로그인해주세요.</h4>
			<hr>
			<p @click="tryAgain">확인</p>
    </div>
	</div>
</template>

<script>
const session = window.sessionStorage;
export default {
	methods: {
		tryAgain: function () {
			const authInst = window.gapi.auth2.getAuthInstance();
          console.log('signout called', authInst)
          authInst.signOut()
          .then(() => {
            // eslint-disable-next-line
            console.log('User Signed Out!!!');
            authInst.disconnect();
            session.clear();
          })
			this.$store.commit('pwchangeConfirmModalActivate')
      location.reload()
		}
	},
}
</script>

<style scoped>
#login_fail {
	display: flex;
	justify-content: center;
	align-items: center;
	width: 100vw;
	height: 100vh;
	background-color: rgb(0, 0, 0, 0.5);
	position: fixed;
	top: 0;
	left: 0;
	z-index: 9999;
}
#modal {
	display: flex;
	flex-direction: column;
	justify-content: center;
	background-color: white;
	border-radius: 20px;
	width: 20vw;
	height: 15vh;
}
p {
	margin: auto;
	font-weight: bold;
	cursor: pointer;
}
hr {
	margin: 0;
}
h4 {
	margin: auto;
	text-align: center;
}
</style>