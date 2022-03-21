<template>
	<div id="return_to_login">
    <div id="modal">
			<h4> 로그인이 필요합니다.</h4>
			<hr>
			<p @click="goLogin">확인</p>
    </div>
	</div>
</template>

<script>
export default {
	methods: {
		goLogin: function () {
			this.$store.commit('ReturnToLoginModalActivate')
			this.$router.push({name: 'Login'})
		}
	}
}
</script>

<style scoped>
#return_to_login {
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
	width: 19rem;
	height: 11rem;
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