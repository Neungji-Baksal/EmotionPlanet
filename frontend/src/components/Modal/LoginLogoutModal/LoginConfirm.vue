<template>
	<div id="login_confirm_modal">
    <div id="modal">
		<div id="modal_header">
			<h4>여행을 시작하겠습니다</h4>
			<img src="@/assets/images/etc/rocket2.png" alt="">
		</div>			
		<hr>
		<p @click="goEmotionTest">확인</p>
    </div>
	</div>
</template>

<script>
export default {
	methods: {
		goEmotionTest: function () {
			this.$store.commit('loginConfirmModalActivate')
			console.log(this.$route.name)
			this.$router.push ({name: 'EmotionTest'})
		}
	}
}
</script>

<style scoped>
#login_confirm_modal {
	display: flex;
	justify-content: center;
	align-items: center;
	width: 100%;
	height: 100%;
	background-color: rgb(0, 0, 0, 0.5);
	position: fixed;
	top: 0;
	left: 0;
	z-index: 999;
}
#modal {
	display: flex;
	flex-direction: column;
	justify-content: center;
	background-color: white;
	border-radius: 30px;
	width: 19rem;
	height: 13rem;
}
p {
	margin: auto;
	font-weight: bold;
	cursor: pointer;
	font-size: 1.25rem;
}
hr {
	margin: 0;
}
h4 {
	margin-top: auto;
	margin-bottom: auto;
	margin-right: 0.4rem;
	text-align: center;
	font-weight: bold;
}
#modal_header {
	display: flex;
	justify-content: center;
	height: 50%;
}
img {
	width: 1.9rem;
	height: 1.9rem;
	margin-top: auto;
	margin-bottom: auto;
}
</style>