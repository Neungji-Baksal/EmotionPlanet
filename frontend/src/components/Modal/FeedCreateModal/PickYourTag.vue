<template>
	<div id="pick_your_tag_modal">
    <div id="modal">
			<h4>행동 태그를 골라주세요!</h4>
            <p id="content"><span style="color: crimson;">1개</span>의 행동태그만 고를 수 있어요.</p>
			<hr>
			<p id="okay" @click="goBack">확인</p>
    </div>
	</div>
</template>

<script>
export default {
	methods: {
		goBack: function () {
			// console.log('여기옴')
			// console.log(this.$store.state.userInfo)
			this.$store.commit('pickYourTagModalActivate')
		}
	}
}
</script>

<style scoped>
#pick_your_tag_modal {
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
#content {
	margin: 0.5rem auto 2rem;
	font-weight: bold;
	font-size: 0.9rem;
}
#okay {
	margin: auto;
	font-weight: bold;
	cursor: pointer;
	font-size: 1.25rem;
}
hr {
	margin: 0;
}
h4 {
	margin: 1rem auto;
	text-align: center;
	font-weight: bold;
}
</style>