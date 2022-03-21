<template>
	<div id="logout_modal">
		<div id="modal">
			<h3 id="content">여행을 그만둘까요?😭</h3>
			<hr>
			<div id="footer">
				<div id="text1">
					<!-- <button id="footer-btn" style="background-color: #777777;" @click="signout">네</button> -->
					<p style="color: red; font-size: 1.3rem; font-weight: bold; cursor: pointer;" @click="signout">네</p>
				</div>
				<div>
					<!-- <button id="footer-btn" @click="cancel">아니오</button> -->
					<p style="font-size: 1.3rem; font-weight: bold; cursor: pointer;" @click="cancel">아니오</p>
				</div>
			</div>
		</div>
	</div>
</template>

<script>
const session = window.sessionStorage
export default {
	methods: {
		cancel: function () {
			this.$store.commit('logoutModalActivate')
		},
		signout () {
			const authInst = window.gapi.auth2.getAuthInstance();
			console.log('signout called', authInst)
			authInst.signOut()
			.then(() => {
				// eslint-disable-next-line
				console.log('User Signed Out!!!');
				authInst.disconnect();
				session.clear();
			})
			.then(() => {
				window.location.reload()
			})
			.catch(() => alert('fail'))
		},
	}
}
</script>

<style scoped>
#logout_modal {
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
	background-color: white;
	border-radius: 20px;
	width: 19rem;
	height: 13rem;
	text-align: center;
	color: black;
}
#content {
	font-weight: bold;
	margin: auto;

}
#footer {
	display: flex;
	flex-direction: row;
	margin-top: auto;
	margin-bottom: auto;
	justify-content: space-evenly;
}
/* #footer-btn {
	background-color: #5E39B3;
	margin: auto;
	font-weight: bold;
	font-size: 1.1rem;
	color: white;
	width: 4rem;
	height: 2.5rem;
	border: none;
	border-radius: 30px;
} */
hr {
	margin: 0rem;
}

</style>