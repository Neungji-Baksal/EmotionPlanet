<template>
  <div id="search_body">
    <div id="triangle"></div>
    <section id="search_header">
      <div id="tab_head">
        <div id="tabs">
          <p @mousedown="toggleTag" :class="onTag ? 'active': 'inactive'">이야기</p>
          <p @mousedown="toggleUser" :class="onUser ? 'active': 'inactive'">여행자</p>
          <p @mousedown="togglePick" :class="onPick ? 'active': 'inactive'">찜 목록</p>
        </div>
      </div>
    </section>
    <section id="search_content">
      <search-tag v-if="onTag"></search-tag>
      <search-user v-if="onUser"></search-user>
      <search-pick v-if="onPick"></search-pick>
    </section>
    <section id="footer">
      <button id="cancel" @click="cancel">닫기</button>
    </section>
    <div id="other-side" @click="cancel">
    </div>
  </div>
</template>

<script>
import SearchTag from './SearchTag.vue'
import SearchUser from './SearchUser.vue'
import SearchPick from './SearchPick.vue'

export default {
  name: 'Search',
  components: { SearchTag, SearchUser, SearchPick },
  data() {
    return {
      onTag: true,
      onUser: false,
      onPick: false,
    }
  },
  methods: {
    cancel() {
      this.$emit('cancel')
    },
    toggleTag: function () {
      this.onTag = true
      this.onUser = false
      this.onPick = false
    },
    toggleUser: function () {
      this.onUser = true
      this.onTag = false
      this.onPick = false
    },
    togglePick: function () {
      this.onUser = false
      this.onTag = false
      this.onPick = true
    },
  }
}
</script>

<style scoped>
  #search_body {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    background-color: white;
  }
  #triangle {
  width: 0px;
  height: 0px;
  border-bottom: 20px solid gainsboro;
  border-left: 30px solid transparent;
  border-right: 30px solid transparent;
  position: absolute;
  top: -250%;
  right: 57%;  
  }
  #search_header {
    z-index: 22;
    display: flex;
    justify-content: center;
    align-items: center;
    background-color: white;
    width: 100%;
    min-width: 300px;
    height: 10%;
    min-height: 55px;
    border-radius: 10px 10px 0 0;
    border-top: 0.15rem solid gainsboro;
    border-left: 0.15rem solid gainsboro;
    border-right: 0.15rem solid gainsboro;
    position: relative;
  }
  
  #search_content {
    overflow: auto;
    display: flex;
    background-color: white !important;
    width: 100%;
    min-width: 300px;
    height: 80%;
    min-height: 300px;
    border-left: 0.15rem solid gainsboro;
    border-right: 0.15rem solid gainsboro;
  }

  h3 {
    font-size: 1.25rem;
    font-weight: bold;
    margin: 0;
  }

  p {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
  }

  .inactive {
    color: #777777;
    font-size: 1.2rem;
    font-weight: bold;
  }

  .active {
    border-bottom: 0.2rem solid #5E39B3;
  }
  #tab_head {
    z-index: inherit;
    width: 100%;
    display: flex;
    flex-direction: row;
  }
  #tabs {
    width: 100%;
    display: flex;
    flex-direction: row;
    justify-content: space-around;
  }
  #footer {
    background-color: white;
    width: 100%;
    min-width: 300px;
    height: 10%;
    min-height: 55px;
    border-radius: 0 0 10px 10px;
    border: 0.15rem solid gainsboro;
    text-align: right;
  }
  #cancel {
    background-color: rgb(94, 57, 179);
    color: white;
    border-radius: 30px;
    width: 3rem;
    height: 2rem;
    margin-top: 0.5rem;
    margin-right: 0.5rem;
    border: none;
    font-weight: bold;
  }

  #other-side {
    width: 100vw;
    height: 100vh;
    position: fixed;
    top: 0;
    left: 0;
    z-index: -1;
  }
</style>