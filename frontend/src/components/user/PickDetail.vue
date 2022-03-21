<template>
  <div id="pick-item-container" v-if="pick">
    <h1>{{ pick.name }}</h1>
    <div id="pick-item-header">
      <img :class="{'movie-poster':pick.type==1}" :src="selectedItem.imgLink" :alt="selectedItem.title">
      <table>
        <tr @click="selected = idx" v-for="(item, idx) of items" :key="idx" :class="{ 'selected':selected == idx }">
          {{item}}
        </tr>
      </table>
    </div>
    <div id="pick-item-body">
      <span class="pick-item-info" v-for="key of ['title', 'author', 'descr', 'year', 'imgLink']" :key="key">
        <h5>{{ key }}</h5>
        <p v-if="selectedItem[key]">{{ selectedItem[key] }}</p>
        <p v-else>-</p>
      </span>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

const session = window.sessionStorage;
export default {
  data(){
    return {
      pick:null,
      selected: 0,
    }
  },
  props: {
    pickNo: String,
  },
  computed: {
    selectedItem(){
      if (this.pick){
        return this.pick.contentsListData[this.selected]
      }
      return 0
    },
    items(){
      let temp=[]
      if (this.pick){
        this.pick.contentsListData.forEach(ele => {
          if(this.pick.type==0){
            temp.push(`${ele.author} - ${ele.title}`)
          }
          else{
            temp.push(`${ele.title}`)
          }
        });
      }
      return temp
    }
  },
  created(){
		let headers = {
			'at-jwt-access-token': session.getItem('at-jwt-access-token'),
			'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
		};

		axios({
			method:'get',
			url:`/api/pick/${this.pickNo}`,
			headers:headers,
		})
		.then((res) => {
			if(res.headers['at-jwt-access-token'] != session.getItem('at-jwt-access-token')){
				session.setItem('at-jwt-access-token', "");
				session.setItem('at-jwt-access-token', res.headers['at-jwt-access-token']);
				console.log("Access Token을 교체합니다!!!")
			}
			this.pick=res.data
      this.$store.commit('load', false)
		})
		.catch((error) => {
			console.log(error);
		})
		.finally(() => {
			console.log('피드 가져오기 클리어');
		});
  }
}
</script>

<style scoped>
  h1 {
    width: 100%;
    padding: 1rem;
  }

  table{
    overflow: auto;
  }
  img {
    width: 40%;
    height: inherit;
    aspect-ratio: 1/1;
    padding: 0.5rem;
  }

  tr {
    width: 100%;
    padding: 0.5rem;
    border-bottom: 1px #cccccc solid;
    cursor: pointer;
    text-align: start;
  }

  h5 {
    width: 20%;
    font-size: 1.25rem;
    font-weight: bold;
    text-align: start;
  }

  p {
    width: 80%;
    word-break: break-all;
    font-size: 1rem;
    margin: 0;
    text-align: start;
  }

  #pick-item-container {
    display: flex;
    flex-direction: column;
    width: 80%;
    margin: 3rem;
  }

  #pick-item-header {
    display: flex;
    width: 100%;
    max-height: 40%;
    border: 2px #cccccc solid;
  }

  #pick-item-header table {
    width: 100%;
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
    align-items: flex-start;
    border-left: 1px #cccccc solid;
    overflow: auto;
  }

  #pick-item-body {
    display: flex;
    flex-direction: column;
    /* width: 100%; */
    aspect-ratio: 3/1;
    margin-top: 1rem;
    border: 2px #cccccc solid;
  }

  .movie-poster {
    aspect-ratio: 1/1.5;
  }

  .pick-item-info {
    display: flex;
    justify-content: stretch;
    align-content: center;
    width: 100%;
    padding: 0.5rem;
  }

  .selected {
    background-color: #cccccc;
    font-weight: bold;
  }
</style>