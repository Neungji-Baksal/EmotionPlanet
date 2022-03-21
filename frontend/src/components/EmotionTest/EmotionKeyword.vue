<template>
  <button id="emotion_btn" @click="check"
  :class="isChecked ? 'checked' : 'blank'">
    {{ keyword.name }}
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
    keyword: Object
  },
  methods: {
    check: function(){
      this.isChecked = !this.isChecked
      
      this.$emit('checked', this.keyword)
    }
  }
}
</script>

<style scoped>
  #emotion_btn {
    display: flex;
    justify-content: center;
    align-self: center;
    padding: 0.25rem 1rem;
    margin: 0.75rem;
  }

  .blank {
    background-color: white;
    color: black;
    border: 3px #5E39B3 solid;
  }
</style>