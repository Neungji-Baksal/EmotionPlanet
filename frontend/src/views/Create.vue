<template>
  <div id="create_container">
    <div id="create_modal">
      <create-img v-if="page==0" @out="out" @next-page="page++" />
      <create-tag v-if="page==1" @out="out" @before-page="page--" @next-page="page++" />
      <create-text v-if="page==2" @out="out" @before-page="page--" />
    </div>
  </div>
</template>

<script>
import CreateImg from '@/components/Create/CreateImg'
import CreateTag from '@/components/Create/CreateTag'
import CreateText from '@/components/Create/CreateText'

export default {
  data(){
    return {
      page: 0,
      createActive: null
    }
  },
  components: {
    CreateImg,
    CreateTag,
    CreateText
  },
  methods: {
    out(){
      this.$store.commit('feedOut')
    }
  },
  mounted(){
   const container = document.getElementById('create_container')
   container.setAttribute('style', `height:${window.innerHeight}px`)
  }
}
</script>

<style scoped>
  #create_container {
    display: flex;
    justify-content: center;
    align-items: center;
    width: 100%;
    background-color: rgb(0, 0, 0, 0.5);
    position: fixed;
    top: 0;
    left: 0;
    z-index: 999;
  }

  #create_modal {
    display:flex;
    flex-direction: column;
    justify-content: flex-start;
    align-items: center;
    width: 35rem;
    height: 35rem;
    background-color: white;
    border: 2px #cccccc solid;
    border-radius: 20px;
    border-style: solid; 
  }
</style>