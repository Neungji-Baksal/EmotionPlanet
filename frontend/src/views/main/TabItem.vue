<template>
  <div @click="$emit('input', id)" :class="[active, 'tab']">
    {{ label }}
  </div>
</template>

<script>
export default {
  props: {
    id: Number,
    label: String,
    value: Number
  },
  computed: {
    active() {
      return this.value === this.id ? 'active' : false
    }
  }
}
</script>

<style scoped>
 div{
  margin: 1rem 1.2rem;
  font-size: 2rem; 
  font-weight: bold;
 }
 
.tab {
  border-radius: 2px 2px 0 0;
  background:none;
  color: #777777;
  line-height: 24px;
  margin-bottom:0;
}
.tab:hover {
}
.active {
  padding-bottom:1rem;
  border-bottom: 0.2rem solid rgb(94, 57, 179);
  color:black;
}
</style>