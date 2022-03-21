<template>
  <button @click="checked" :class="{'checked':isChecked}">
    {{ tag }}
  </button>   
</template>

<script>
export default {
  data: function(){
    return {
      isChecked: false
    }
  },
  props: { 
    tag: String
  },
  methods: {
    checked: function(){
      this.isChecked = !this.isChecked
      this.$emit('checked', this.tag)
      this.$emit('selected', this.isChecked)
    }
  }
}
</script>

<style scoped>
  button {
    background-color: white;
    color: black;
    font-size: 1rem;
    font-weight: bold;
    border: 3px #cccccc solid;
    border-radius: 20px;
    margin: 0.5rem;
    padding: 0 1rem;
    cursor: pointer;
    line-height: 2rem;
  }

  .checked {
    background-color: #5E39B3;
    border: 3px #5E39B3 solid;
  }
</style>