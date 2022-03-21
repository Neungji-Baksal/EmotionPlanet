<template>
	<div id="pick_your_images_modal">
    <div id="modal">
			<h4>이미지를 골라주세요</h4>
			<hr>
			<p @click="goBack">확인</p>
    </div>
	</div>
</template>

<script>
export default {
	methods: {
		goBack: function () {
			// console.log('여기옴')
			// console.log(this.$store.state.userInfo)
			this.$store.commit('pickYourImageModalActivate')
		}
	}
}
</script>

<style scoped>
#pick_your_images_modal {
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
	width: 18rem;
	height: 10rem;
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
	margin: auto;
	text-align: center;
	font-weight: bold;
}
</style>