<template>
  <div>
    <div>
      <div id="container">
        <div>
          <img
            id="planet"
            :src="require('@/assets/images/emotions/' + tmp.img)"
          />
        </div>
        <div id="header">
          <h1 style="font-size: 2.5rem; font-weight: bold; margin: auto;">어서오세요!</h1>
          <span id="planet_name" :style="{ color: tmp.color }">{{
            tmp.name
          }}</span>
          <span style="font-size: 2.5rem; font-weight: bold">입니다</span>
        </div>
      </div>
    </div>
    <div class="tab">
      <div id="tab_names">
        <p @click="tab = 0" :class="tab == 0 ? 'active' : 'inactive'" style="margin-right:1rem; margin-left:2rem;">떠나기</p>
        <p @click="tab = 1" :class="tab == 1 ? 'active' : 'inactive'" style="margin-left:1rem;">탐험하기</p>
      </div>
      <div id="refresh">
        <p style="font-weight: bold; font-size: 1.5rem;">좀 더 놀기</p>
        <img src="@/assets/images/icons/refresh.png" @click="reload"  id="refresh_btn">
      </div>
    </div>
    <div id="recommend_list">
      <music-list :tab="tab" @comp="prepared ++"></music-list>
      <movie-list :tab="tab" @comp="prepared ++"></movie-list>
      <active-list :tab="tab" @comp="prepared ++"></active-list>
    </div>
  </div>
</template>

<script>
import MusicList from "./MusicList.vue";
import ActiveList from "./ActiveList.vue";
import MovieList from "./MovieList.vue";
export default {
  components: { MusicList, MovieList, ActiveList },
  props: {
    userInfo: Object,
  },
  data: function () {
    return {
      planetStyles: [
        { id: 1, name: "행복행성", img: "happy.png", color: "#6BD9E8" },
        { id: 2, name: "우울행성", img: "depressed.png", color: "#2A61F0" },
        { id: 3, name: "떠돌이행성", img: "space-station.png", color: "#ABBECA" },
        { id: 4, name: "공포행성", img: "fear.png", color: "#ED5A8E" },
        { id: 5, name: "깜짝행성", img: "surprised.png", color: "#FEA95C" },
        { id: 6, name: "분노행성", img: "rage.png", color: "#FB5D38" },
        { id: 7, name: '떠돌이행성', img: "spaceship.png", color: '#FCBB74' },
      ],
      tab: 0,
      prepared: 0
    };
  },
  computed: {
    tmp: function () {
      const mood = this.$store.state.userInfo.mood;
      const style = this.planetStyles.find((el) => el.id === mood) || {};
      return style;
    },
  },
  watch:{
    prepared(){
      if (this.prepared == 3){
        this.$store.commit('load', false)
        console.log('loaded!!!')
      }
    }
  },
  methods: {
    reload() {
      location.reload()
      this.$store.state.loading = true
    },
  },
};
</script>

<style scoped>
p {
  margin: 5px;
  text-align: center;
}
#planet {
  width: 8rem;
  height: 8rem;
}
#planet_name {
  font-size: 3rem;
  font-weight: bold;
}
#container {
  /* border: 2px solid black; */
  display: flex;
  width: 100%;
  padding-top: 1rem;
  background-color: white;
  padding: 2rem;
  justify-content: center;
  border-bottom: 0.15rem solid gainsboro;
}
#header {
  text-align: left;
  margin-left: 5px;
  margin-top: auto;
  margin-bottom: auto;
}
.tab {
  display: flex;
  flex-direction: column;
  font-size: 1.2rem;
  font-weight: bold;
  color: #777777;
}

#tab_names {
  display: flex;
  justify-content: center;
  margin-top: 0.5rem;
  font-size: 1.5rem;
  font-weight: bold;
  color: #777777;
}
.active {
  color: rgb(94, 57, 179);
}

#refresh {
  display: flex;
  width: 90%;
  justify-content: right;
  align-items: center;
  margin: 0rem 1rem 2rem 4rem;
}
#refresh_btn {
  width: 2.5rem;
  height: 2.5rem;
  cursor: pointer;
}

</style>