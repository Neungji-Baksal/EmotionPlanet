<template>
  <section id="setting_container">
    <router-view/>
  </section>
</template>

<script>

export default {
//   components: {
//     Navigation,
//   }
}
</script>

<style scoped>
  #setting {
    width: 100vw;
  }

  #setting_container {
    width: 50%;
    min-width: 700px;
    min-height: 100vh;
    margin: auto;
    border-left: 1px solid #cccccc;
    border-right: 1px solid #cccccc;
    background-color: white;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: flex-start;
  }
</style>
