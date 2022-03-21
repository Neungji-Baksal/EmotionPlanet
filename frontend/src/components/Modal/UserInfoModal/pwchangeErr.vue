<template>
	<div id="login_fail">
    <div id="modal">
			<h4>비밀번호를 다시 확인해주세요.</h4>
			<hr>
			<p @click="tryAgain">확인</p>
    </div>
	</div>
</template>

<script>

export default {
	methods: {
		tryAgain: function () {
			// console.log('여기옴')
			// console.log(this.$store.state.userInfo)
			this.$store.commit('pwchangeErrModalActivate')
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